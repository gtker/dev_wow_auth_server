mod protocol_differences;

use io::{Read, Write};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread::sleep;
use std::time::Duration;
use std::{io, thread};
use wow_login_messages::all::{
    CMD_AUTH_LOGON_CHALLENGE_Client, CMD_AUTH_RECONNECT_CHALLENGE_Client,
};
use wow_login_messages::errors::ExpectedOpcodeError;
use wow_login_messages::helper::{expect_client_message, read_initial_message, InitialMessage};
use wow_login_messages::ServerMessage;
use wow_srp::normalized_string::NormalizedString;
use wow_srp::server::{SrpProof, SrpServer, SrpVerifier};
use wow_srp::PublicKey;

use crate::protocol_differences::{
    get_cmd_auth_logon_proof, get_cmd_auth_reconnect_proof,
    send_cmd_auth_logon_challenge_server_success, send_cmd_auth_logon_proof_failure,
    send_cmd_auth_logon_proof_success, send_cmd_auth_reconnect_challenge,
    send_cmd_auth_reconnect_proof_incorrect_password, send_cmd_auth_reconnect_proof_success,
};
use clap::Parser;
use log::{error, info};

#[derive(Debug, Copy, Clone)]
pub(crate) enum LoginProtocolVersion {
    Two,
    Three,
    Five,
    Six,
    Seven,
    Eight,
}

#[derive(Debug, Copy, Clone)]
pub(crate) enum ReconnectProtocolVersion {
    Two,
    Five,
    Six,
    Seven,
    Eight,
}

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Socket of authentication/login server. Default is '127.0.0.1:3724'.
    #[arg(short, long)]
    auth: Option<SocketAddr>,
    /// Socket of world server (where the realm list points to). Default is '127.0.0.1:8085'.
    #[arg(short, long)]
    world: Option<SocketAddr>,
    /// Socket of reply server (where you query session keys). Default is '127.0.0.1:8086'.
    #[arg(short, long)]
    reply: Option<SocketAddr>,
}

#[derive(Debug, Clone, Copy)]
struct Options {
    auth: SocketAddr,
    world: SocketAddr,
    reply: SocketAddr,
}

impl Options {
    pub fn new(cli: Cli) -> Self {
        Self {
            auth: if let Some(p) = cli.auth {
                p
            } else {
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 3724)
            },
            world: if let Some(p) = cli.world {
                p
            } else {
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8085)
            },
            reply: if let Some(p) = cli.reply {
                p
            } else {
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8086)
            },
        }
    }
}

fn main() {
    simple_logger::SimpleLogger::new().env().init().unwrap();

    let cli = Cli::parse();

    let users = Arc::new(Mutex::new(HashMap::new()));

    let reply_users = users.clone();

    let options = Options::new(cli);

    let auth_thread = thread::spawn(move || auth(users, &options));

    let reply_thread = thread::spawn(move || reply(reply_users, &options));

    reply_thread.join().unwrap();
    auth_thread.join().unwrap();
}

fn reply(users: Arc<Mutex<HashMap<String, SrpServer>>>, options: &Options) {
    let listener = TcpListener::bind(options.reply).unwrap();
    info!("[REPLY] Listening for queries on {}", options.reply);

    loop {
        let (stream, _) = listener.accept().unwrap();

        let users = users.clone();
        thread::spawn(move || {
            let peer_address = stream.peer_addr().unwrap();
            info!("[REPLY] Connected to {}", peer_address);

            match handle_reply(stream, users) {
                Ok(_) => {}
                Err(_) => info!("[REPLY] Lost connection to {}", peer_address),
            }
        });
    }
}

fn handle_reply(
    mut stream: TcpStream,
    users: Arc<Mutex<HashMap<String, SrpServer>>>,
) -> io::Result<()> {
    let mut buf = [0_u8; 1];
    loop {
        stream.read_exact(&mut buf)?;

        let name_length = buf[0];

        let mut v = Vec::with_capacity(name_length.into());

        for _ in 0..name_length {
            stream.read_exact(&mut buf)?;
            v.push(buf[0]);
        }

        let name = match String::from_utf8(v.clone()) {
            Ok(s) => s,
            Err(e) => {
                error!("[REPLY] Invalid UTF-8 string name: '{:?}'", v);
                return Err(io::Error::new(io::ErrorKind::Other, e));
            }
        };
        info!("[REPLY] '{}' Received query", name);

        let session_key = {
            let u = users.lock().unwrap();
            if let Some(u) = u.get(&name) {
                Some(*u.session_key())
            } else {
                None
            }
        };

        let vec_size = 2 + name.as_bytes().len() + if session_key.is_some() { 40 } else { 0 };
        let mut buffer = Vec::with_capacity(vec_size);

        buffer.push(name.len() as u8);

        for v in name.as_bytes() {
            buffer.push(*v);
        }

        if let Some(session_key) = session_key {
            info!("[REPLY] '{}': Session key found: {:?}", name, session_key);
            buffer.push(1);

            for v in session_key {
                buffer.push(v);
            }
        } else {
            info!("[REPLY] '{}': Session key not found", name);
            buffer.push(0);
        }

        stream.write_all(&buffer)?;
    }
}

fn auth(users: Arc<Mutex<HashMap<String, SrpServer>>>, options: &Options) {
    let listener = TcpListener::bind(options.auth).unwrap();

    let options = *options;

    info!("[AUTH] Listening for authentications on {}", options.auth);
    loop {
        let (stream, _) = listener.accept().unwrap();

        let users = users.clone();
        thread::spawn(move || {
            let peer_addr = stream.peer_addr().unwrap();
            info!("[REPLY] Connected to {}", peer_addr);
            match handle_auth(stream, users, &options) {
                Ok(_) => {}
                Err(_) => {
                    error!("[AUTH] Connection lost to {}", peer_addr)
                }
            }
        });
    }
}

fn handle_auth(
    mut stream: TcpStream,
    users: Arc<Mutex<HashMap<String, SrpServer>>>,
    options: &Options,
) -> io::Result<()> {
    let opcode = read_initial_message(&mut stream);
    let opcode = match opcode {
        Ok(o) => o,
        Err(e) => {
            match &e {
                ExpectedOpcodeError::Opcode(o) => {
                    error!("[AUTH] invalid opcode {}", o)
                }
                ExpectedOpcodeError::Parse(e) => {
                    error!("[AUTH] parse error {:#?}", e)
                }
            }
            return Err(io::Error::new(io::ErrorKind::Other, e));
        }
    };

    match opcode {
        InitialMessage::Logon(l) => match l.protocol_version {
            2 => login(stream, l, users, options, LoginProtocolVersion::Two),
            3 => login(stream, l, users, options, LoginProtocolVersion::Three),
            5 => login(stream, l, users, options, LoginProtocolVersion::Five),
            6 => login(stream, l, users, options, LoginProtocolVersion::Six),
            7 => login(stream, l, users, options, LoginProtocolVersion::Seven),
            8 => login(stream, l, users, options, LoginProtocolVersion::Eight),
            v => panic!("unknown login version {v}"),
        },
        InitialMessage::Reconnect(r) => match r.protocol_version {
            2 => reconnect(stream, r, users, options, ReconnectProtocolVersion::Two),
            5 => reconnect(stream, r, users, options, ReconnectProtocolVersion::Five),
            6 => reconnect(stream, r, users, options, ReconnectProtocolVersion::Six),
            7 => reconnect(stream, r, users, options, ReconnectProtocolVersion::Seven),
            8 => reconnect(stream, r, users, options, ReconnectProtocolVersion::Eight),
            v => panic!("unknown reconnect version {v}"),
        },
    }

    Ok(())
}

fn reconnect(
    mut stream: TcpStream,
    r: CMD_AUTH_RECONNECT_CHALLENGE_Client,
    users: Arc<Mutex<HashMap<String, SrpServer>>>,
    options: &Options,
    protocol_version: ReconnectProtocolVersion,
) {
    info!(
        "[AUTH] '{}' Reconnect version: {}",
        r.account_name, r.protocol_version
    );
    let username = r.account_name.clone();

    let server_reconnect_challenge_data = *users
        .lock()
        .unwrap()
        .get(&r.account_name)
        .unwrap()
        .reconnect_challenge_data();

    send_cmd_auth_reconnect_challenge(
        &mut stream,
        protocol_version,
        server_reconnect_challenge_data,
    )
    .unwrap();

    let (proof_data, client_proof) =
        get_cmd_auth_reconnect_proof(&mut stream, protocol_version).unwrap();

    let success = {
        match users.lock().unwrap().get_mut(&r.account_name) {
            None => false,
            Some(server) => server.verify_reconnection_attempt(proof_data, client_proof),
        }
    };

    if !success {
        send_cmd_auth_reconnect_proof_incorrect_password(&mut stream, protocol_version).unwrap();

        return;
    }

    send_cmd_auth_reconnect_proof_success(&mut stream, protocol_version).unwrap();

    match protocol_version {
        ReconnectProtocolVersion::Two => {
            print_version_2_3_realm_list(stream, &username, options);
        }
        ReconnectProtocolVersion::Five => {
            print_version_5_realm_list(stream, &username, options);
        }
        ReconnectProtocolVersion::Six => {
            print_version_6_realm_list(stream, &username, options);
        }
        ReconnectProtocolVersion::Seven => {
            print_version_7_realm_list(stream, &username, options);
        }
        ReconnectProtocolVersion::Eight => {
            print_version_8_realm_list(stream, &username, options);
        }
    }
}

fn login(
    mut stream: TcpStream,
    l: CMD_AUTH_LOGON_CHALLENGE_Client,
    users: Arc<Mutex<HashMap<String, SrpServer>>>,
    options: &Options,
    protocol_version: LoginProtocolVersion,
) {
    info!(
        "[AUTH] '{}' Login version: {}",
        l.account_name, l.protocol_version
    );
    let p = get_proof(&l.account_name);
    let username = l.account_name;

    send_cmd_auth_logon_challenge_server_success(
        &mut stream,
        protocol_version,
        &username,
        *p.server_public_key(),
        *p.salt(),
    )
    .unwrap();

    let (client_public_key, client_proof) =
        get_cmd_auth_logon_proof(&mut stream, protocol_version).unwrap();

    let (p, proof) = if let Ok(a) = p.into_server(
        PublicKey::from_le_bytes(&client_public_key).unwrap(),
        client_proof,
    ) {
        a
    } else {
        send_cmd_auth_logon_proof_failure(&mut stream, protocol_version, &username).unwrap();
        sleep(Duration::from_secs(1));
        return;
    };

    send_cmd_auth_logon_proof_success(&mut stream, protocol_version, &username, proof).unwrap();

    users.lock().unwrap().insert(username.clone(), p);

    return;
    match protocol_version {
        LoginProtocolVersion::Two | LoginProtocolVersion::Three => {
            print_version_2_3_realm_list(stream, &username, options);
        }
        LoginProtocolVersion::Five => {
            print_version_5_realm_list(stream, &username, options);
        }
        LoginProtocolVersion::Six => {
            print_version_6_realm_list(stream, &username, options);
        }
        LoginProtocolVersion::Seven => {
            print_version_7_realm_list(stream, &username, options);
        }
        LoginProtocolVersion::Eight => {
            print_version_8_realm_list(stream, &username, options);
        }
    }
}

fn get_proof(username: &str) -> SrpProof {
    let username = NormalizedString::new(username.to_string()).unwrap();
    let password = NormalizedString::new(username.to_string()).unwrap();
    SrpVerifier::from_username_and_password(username, password).into_proof()
}

fn print_version_2_3_realm_list(mut stream: TcpStream, username: &str, options: &Options) {
    use wow_login_messages::version_2::*;

    while (expect_client_message::<CMD_REALM_LIST_Client, _>(&mut stream)).is_ok() {
        CMD_REALM_LIST_Server {
            realms: vec![Realm {
                realm_type: RealmType::PlayerVsEnvironment,
                flag: RealmFlag::empty(),
                name: "Tester".to_string(),
                address: options.world.to_string(),
                population: Default::default(),
                number_of_characters_on_realm: 0,
                category: Default::default(),
                realm_id: 0,
            }],
        }
        .write(&mut stream)
        .unwrap();
        info!("[AUTH] '{}' Sent Version 2/3 Realm List", username);
    }
}

fn print_version_5_realm_list(mut stream: TcpStream, username: &str, options: &Options) {
    use wow_login_messages::version_5::*;

    while (expect_client_message::<CMD_REALM_LIST_Client, _>(&mut stream)).is_ok() {
        CMD_REALM_LIST_Server {
            realms: vec![
                Realm {
                    realm_type: RealmType::PlayerVsEnvironment,
                    locked: false,
                    flag: RealmFlag::empty(),
                    name: "Empty".to_string(),
                    address: options.world.to_string(),
                    population: Population::Other(u32::from_le_bytes(0.0_f32.to_le_bytes())),
                    number_of_characters_on_realm: 1,
                    category: RealmCategory::Default,
                    realm_id: 0,
                },
                Realm {
                    realm_type: RealmType::PlayerVsEnvironment,
                    locked: false,
                    flag: RealmFlag::empty().set_FORCE_BLUE_RECOMMENDED(),
                    name: "Blue recommended".to_string(),
                    address: options.world.to_string(),
                    population: Population::Other(u32::from_le_bytes(0.0_f32.to_le_bytes())),
                    number_of_characters_on_realm: 1,
                    category: RealmCategory::Default,
                    realm_id: 0,
                },
                Realm {
                    realm_type: RealmType::PlayerVsEnvironment,
                    locked: false,
                    flag: RealmFlag::empty().set_FORCE_RED_FULL(),
                    name: "Red full".to_string(),
                    address: options.world.to_string(),
                    population: Population::Other(u32::from_le_bytes(0.0_f32.to_le_bytes())),
                    number_of_characters_on_realm: 1,
                    category: RealmCategory::Default,
                    realm_id: 0,
                },
                Realm {
                    realm_type: RealmType::PlayerVsEnvironment,
                    locked: false,
                    flag: RealmFlag::empty().set_OFFLINE(),
                    name: "Offline".to_string(),
                    address: options.world.to_string(),
                    population: Population::Other(u32::from_le_bytes(0.0_f32.to_le_bytes())),
                    number_of_characters_on_realm: 1,
                    category: RealmCategory::Default,
                    realm_id: 0,
                },
                Realm {
                    realm_type: RealmType::PlayerVsEnvironment,
                    locked: false,
                    flag: RealmFlag::empty().set_INVALID(),
                    name: "Invalid".to_string(),
                    address: options.world.to_string(),
                    population: Population::Other(u32::from_le_bytes(0.0_f32.to_le_bytes())),
                    number_of_characters_on_realm: 1,
                    category: RealmCategory::Default,
                    realm_id: 0,
                },
            ],
        }
        .write(&mut stream)
        .unwrap();

        info!("[AUTH] '{}' Sent Version 5 Realm List", username);
    }
}

fn print_version_6_realm_list(mut stream: TcpStream, username: &str, options: &Options) {
    use wow_login_messages::version_6::*;

    while (expect_client_message::<CMD_REALM_LIST_Client, _>(&mut stream)).is_ok() {
        CMD_REALM_LIST_Server {
            realms: vec![
                Realm {
                    realm_type: RealmType::PlayerVsEnvironment,
                    locked: false,
                    flag: RealmFlag::empty(),
                    name: "Empty".to_string(),
                    address: options.world.to_string(),
                    population: Population::Other(u32::from_le_bytes(0.0_f32.to_le_bytes())),
                    number_of_characters_on_realm: 1,
                    category: RealmCategory::Default,
                    realm_id: 0,
                },
                Realm {
                    realm_type: RealmType::PlayerVsEnvironment,
                    locked: false,
                    flag: RealmFlag::empty().set_FORCE_BLUE_RECOMMENDED(),
                    name: "Blue recommended".to_string(),
                    address: options.world.to_string(),
                    population: Population::Other(u32::from_le_bytes(0.0_f32.to_le_bytes())),
                    number_of_characters_on_realm: 1,
                    category: RealmCategory::Default,
                    realm_id: 0,
                },
                Realm {
                    realm_type: RealmType::PlayerVsEnvironment,
                    locked: false,
                    flag: RealmFlag::empty().set_FORCE_RED_FULL(),
                    name: "Red full".to_string(),
                    address: options.world.to_string(),
                    population: Population::Other(u32::from_le_bytes(0.0_f32.to_le_bytes())),
                    number_of_characters_on_realm: 1,
                    category: RealmCategory::Default,
                    realm_id: 0,
                },
                Realm {
                    realm_type: RealmType::PlayerVsEnvironment,
                    locked: false,
                    flag: RealmFlag::empty().set_OFFLINE(),
                    name: "Offline".to_string(),
                    address: options.world.to_string(),
                    population: Population::Other(u32::from_le_bytes(0.0_f32.to_le_bytes())),
                    number_of_characters_on_realm: 1,
                    category: RealmCategory::Default,
                    realm_id: 0,
                },
                Realm {
                    realm_type: RealmType::PlayerVsEnvironment,
                    locked: false,
                    flag: RealmFlag::empty().set_INVALID(),
                    name: "Invalid".to_string(),
                    address: options.world.to_string(),
                    population: Population::Other(u32::from_le_bytes(0.0_f32.to_le_bytes())),
                    number_of_characters_on_realm: 1,
                    category: RealmCategory::Default,
                    realm_id: 0,
                },
            ],
        }
        .write(&mut stream)
        .unwrap();

        info!("[AUTH] '{}' Sent Version 6 Realm List", username);
    }
}

fn print_version_7_realm_list(mut stream: TcpStream, username: &str, options: &Options) {
    use wow_login_messages::version_6::*;

    while (expect_client_message::<CMD_REALM_LIST_Client, _>(&mut stream)).is_ok() {
        CMD_REALM_LIST_Server {
            realms: vec![
                Realm {
                    realm_type: RealmType::PlayerVsEnvironment,
                    locked: false,
                    flag: RealmFlag::empty(),
                    name: "Empty".to_string(),
                    address: options.world.to_string(),
                    population: Population::Other(u32::from_le_bytes(0.0_f32.to_le_bytes())),
                    number_of_characters_on_realm: 1,
                    category: RealmCategory::Default,
                    realm_id: 0,
                },
                Realm {
                    realm_type: RealmType::PlayerVsEnvironment,
                    locked: false,
                    flag: RealmFlag::empty().set_FORCE_BLUE_RECOMMENDED(),
                    name: "Blue recommended".to_string(),
                    address: options.world.to_string(),
                    population: Population::Other(u32::from_le_bytes(0.0_f32.to_le_bytes())),
                    number_of_characters_on_realm: 1,
                    category: RealmCategory::Default,
                    realm_id: 0,
                },
                Realm {
                    realm_type: RealmType::PlayerVsEnvironment,
                    locked: false,
                    flag: RealmFlag::empty().set_FORCE_RED_FULL(),
                    name: "Red full".to_string(),
                    address: options.world.to_string(),
                    population: Population::Other(u32::from_le_bytes(0.0_f32.to_le_bytes())),
                    number_of_characters_on_realm: 1,
                    category: RealmCategory::Default,
                    realm_id: 0,
                },
                Realm {
                    realm_type: RealmType::PlayerVsEnvironment,
                    locked: false,
                    flag: RealmFlag::empty().set_OFFLINE(),
                    name: "Offline".to_string(),
                    address: options.world.to_string(),
                    population: Population::Other(u32::from_le_bytes(0.0_f32.to_le_bytes())),
                    number_of_characters_on_realm: 1,
                    category: RealmCategory::Default,
                    realm_id: 0,
                },
                Realm {
                    realm_type: RealmType::PlayerVsEnvironment,
                    locked: false,
                    flag: RealmFlag::empty().set_INVALID(),
                    name: "Invalid".to_string(),
                    address: options.world.to_string(),
                    population: Population::Other(u32::from_le_bytes(0.0_f32.to_le_bytes())),
                    number_of_characters_on_realm: 1,
                    category: RealmCategory::Default,
                    realm_id: 0,
                },
            ],
        }
        .write(&mut stream)
        .unwrap();

        info!("[AUTH] '{}' Sent Version 7 Realm List", username);
    }
}

fn print_version_8_realm_list(mut stream: TcpStream, username: &str, options: &Options) {
    use wow_login_messages::version_8::*;

    while (expect_client_message::<CMD_REALM_LIST_Client, _>(&mut stream)).is_ok() {
        CMD_REALM_LIST_Server {
            realms: vec![Realm {
                realm_type: RealmType::PlayerVsEnvironment,
                locked: false,
                flag: Default::default(),
                name: "Tester".to_string(),
                address: options.world.to_string(),
                population: Default::default(),
                number_of_characters_on_realm: 0,
                category: RealmCategory::Default,
                realm_id: 0,
            }],
        }
        .write(&mut stream)
        .unwrap();

        info!("[AUTH] '{}' Sent Version 8 Realm List", username);
    }
}
