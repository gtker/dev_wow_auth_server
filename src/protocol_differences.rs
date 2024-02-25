use log::info;
use std::io;
use std::net::TcpStream;
use wow_login_messages::all::ProtocolVersion;
use wow_login_messages::helper::expect_client_message;
use wow_login_messages::{
    version_2, version_3, version_5, version_6, version_7, version_8, Message,
};
use wow_srp::{
    GENERATOR, LARGE_SAFE_PRIME_LITTLE_ENDIAN, PROOF_LENGTH, PUBLIC_KEY_LENGTH,
    RECONNECT_CHALLENGE_DATA_LENGTH, SALT_LENGTH,
};

pub(crate) fn send_cmd_auth_logon_challenge_server_success(
    stream: &mut TcpStream,
    protocol_version: ProtocolVersion,
    username: &str,
    server_public_key: [u8; PUBLIC_KEY_LENGTH as usize],
    salt: [u8; SALT_LENGTH as usize],
) -> io::Result<()> {
    match protocol_version {
        ProtocolVersion::Two => {
            version_2::CMD_AUTH_LOGON_CHALLENGE_Server {
                result: version_2::CMD_AUTH_LOGON_CHALLENGE_Server_LoginResult::Success {
                    server_public_key,
                    generator: vec![GENERATOR],
                    large_safe_prime: LARGE_SAFE_PRIME_LITTLE_ENDIAN.into(),
                    salt,
                    crc_salt: [0; 16],
                },
            }
            .write(stream)?;
        }
        ProtocolVersion::Three => {
            version_3::CMD_AUTH_LOGON_CHALLENGE_Server {
                result: version_3::CMD_AUTH_LOGON_CHALLENGE_Server_LoginResult::Success {
                    server_public_key,
                    generator: vec![GENERATOR],
                    large_safe_prime: LARGE_SAFE_PRIME_LITTLE_ENDIAN.into(),
                    salt,
                    crc_salt: [0; 16],
                    security_flag: version_3::CMD_AUTH_LOGON_CHALLENGE_Server_SecurityFlag::None,
                },
            }
            .write(stream)?;
        }
        ProtocolVersion::Five => {
            version_5::CMD_AUTH_LOGON_CHALLENGE_Server {
                result: version_5::CMD_AUTH_LOGON_CHALLENGE_Server_LoginResult::Success {
                    server_public_key,
                    generator: vec![GENERATOR],
                    large_safe_prime: LARGE_SAFE_PRIME_LITTLE_ENDIAN.into(),
                    salt,
                    crc_salt: [0; 16],
                    security_flag: version_5::CMD_AUTH_LOGON_CHALLENGE_Server_SecurityFlag::None,
                },
            }
            .write(stream)?;
        }
        ProtocolVersion::Six => {
            version_6::CMD_AUTH_LOGON_CHALLENGE_Server {
                result: version_6::CMD_AUTH_LOGON_CHALLENGE_Server_LoginResult::Success {
                    server_public_key,
                    generator: vec![GENERATOR],
                    large_safe_prime: LARGE_SAFE_PRIME_LITTLE_ENDIAN.into(),
                    salt,
                    crc_salt: [0; 16],
                    security_flag: version_6::CMD_AUTH_LOGON_CHALLENGE_Server_SecurityFlag::None,
                },
            }
            .write(stream)?;
        }
        ProtocolVersion::Seven => {
            version_7::CMD_AUTH_LOGON_CHALLENGE_Server {
                result: version_7::CMD_AUTH_LOGON_CHALLENGE_Server_LoginResult::Success {
                    server_public_key,
                    generator: vec![GENERATOR],
                    large_safe_prime: LARGE_SAFE_PRIME_LITTLE_ENDIAN.into(),
                    salt,
                    crc_salt: [0; 16],
                    security_flag: version_7::CMD_AUTH_LOGON_CHALLENGE_Server_SecurityFlag::None,
                },
            }
            .write(stream)?;
        }
        ProtocolVersion::Eight => {
            version_8::CMD_AUTH_LOGON_CHALLENGE_Server {
                result: version_8::CMD_AUTH_LOGON_CHALLENGE_Server_LoginResult::Success {
                    server_public_key,
                    generator: vec![GENERATOR],
                    large_safe_prime: LARGE_SAFE_PRIME_LITTLE_ENDIAN.into(),
                    salt,
                    crc_salt: [0; 16],
                    security_flag: version_8::CMD_AUTH_LOGON_CHALLENGE_Server_SecurityFlag::empty(),
                },
            }
            .write(stream)?;
        }
    }
    info!("[AUTH] '{}' Sent Logon Challenge", username);

    Ok(())
}

pub(crate) fn get_cmd_auth_logon_proof(
    stream: &mut TcpStream,
    protocol_version: ProtocolVersion,
) -> io::Result<(
    [u8; PUBLIC_KEY_LENGTH as usize],
    [u8; PROOF_LENGTH as usize],
)> {
    match protocol_version {
        ProtocolVersion::Two => {
            let m = match expect_client_message::<version_2::CMD_AUTH_LOGON_PROOF_Client, _>(stream)
            {
                Ok(l) => l,
                Err(_) => {
                    return Err(io::Error::new(io::ErrorKind::Other, "error"));
                }
            };
            Ok((m.client_public_key, m.client_proof))
        }
        ProtocolVersion::Three => {
            let m = match expect_client_message::<version_3::CMD_AUTH_LOGON_PROOF_Client, _>(stream)
            {
                Ok(l) => l,
                Err(_) => {
                    return Err(io::Error::new(io::ErrorKind::Other, "error"));
                }
            };
            Ok((m.client_public_key, m.client_proof))
        }
        ProtocolVersion::Five => {
            let m =
                expect_client_message::<version_5::CMD_AUTH_LOGON_PROOF_Client, _>(stream).unwrap();
            Ok((m.client_public_key, m.client_proof))
        }
        ProtocolVersion::Six => {
            let m =
                expect_client_message::<version_6::CMD_AUTH_LOGON_PROOF_Client, _>(stream).unwrap();
            Ok((m.client_public_key, m.client_proof))
        }
        ProtocolVersion::Seven => {
            let m =
                expect_client_message::<version_7::CMD_AUTH_LOGON_PROOF_Client, _>(stream).unwrap();
            Ok((m.client_public_key, m.client_proof))
        }
        ProtocolVersion::Eight => {
            let m = match expect_client_message::<version_8::CMD_AUTH_LOGON_PROOF_Client, _>(stream)
            {
                Ok(l) => l,
                Err(_) => {
                    return Err(io::Error::new(io::ErrorKind::Other, "error"));
                }
            };
            Ok((m.client_public_key, m.client_proof))
        }
    }
}

pub(crate) fn send_cmd_auth_logon_proof_failure(
    stream: &mut TcpStream,
    protocol_version: ProtocolVersion,
    username: &str,
) -> io::Result<()> {
    match protocol_version {
        ProtocolVersion::Two => {
            version_2::CMD_AUTH_LOGON_PROOF_Server {
                result: version_2::CMD_AUTH_LOGON_PROOF_Server_LoginResult::FailIncorrectPassword,
            }
            .write(stream)?;
        }
        ProtocolVersion::Three => {
            version_3::CMD_AUTH_LOGON_PROOF_Server {
                result: version_3::CMD_AUTH_LOGON_PROOF_Server_LoginResult::FailIncorrectPassword,
            }
            .write(stream)?;
        }
        ProtocolVersion::Five => {
            version_5::CMD_AUTH_LOGON_PROOF_Server {
                result: version_5::CMD_AUTH_LOGON_PROOF_Server_LoginResult::FailIncorrectPassword,
            }
            .write(stream)?;
        }
        ProtocolVersion::Six => {
            version_6::CMD_AUTH_LOGON_PROOF_Server {
                result: version_6::CMD_AUTH_LOGON_PROOF_Server_LoginResult::FailIncorrectPassword,
            }
            .write(stream)?;
        }
        ProtocolVersion::Seven => {
            version_7::CMD_AUTH_LOGON_PROOF_Server {
                result: version_7::CMD_AUTH_LOGON_PROOF_Server_LoginResult::FailIncorrectPassword,
            }
            .write(stream)?;
        }
        ProtocolVersion::Eight => {
            version_8::CMD_AUTH_LOGON_PROOF_Server {
                result: version_8::CMD_AUTH_LOGON_PROOF_Server_LoginResult::FailIncorrectPassword,
            }
            .write(stream)?;
        }
    }

    info!("[AUTH] '{}' Sent Logon Proof", username);

    Ok(())
}

pub(crate) fn send_cmd_auth_logon_proof_success(
    stream: &mut TcpStream,
    protocol_version: ProtocolVersion,
    username: &str,
    proof: [u8; PROOF_LENGTH as usize],
) -> io::Result<()> {
    match protocol_version {
        ProtocolVersion::Two => {
            version_2::CMD_AUTH_LOGON_PROOF_Server {
                result: version_2::CMD_AUTH_LOGON_PROOF_Server_LoginResult::Success {
                    server_proof: proof,
                    hardware_survey_id: 0,
                },
            }
            .write(stream)?;
        }
        ProtocolVersion::Three => {
            version_3::CMD_AUTH_LOGON_PROOF_Server {
                result: version_3::CMD_AUTH_LOGON_PROOF_Server_LoginResult::Success {
                    server_proof: proof,
                    hardware_survey_id: 0,
                },
            }
            .write(stream)?;
        }
        ProtocolVersion::Five => {
            version_5::CMD_AUTH_LOGON_PROOF_Server {
                result: version_5::CMD_AUTH_LOGON_PROOF_Server_LoginResult::Success {
                    server_proof: proof,
                    hardware_survey_id: 0,
                    unknown: 0,
                },
            }
            .write(stream)?;
        }
        ProtocolVersion::Six => {
            version_6::CMD_AUTH_LOGON_PROOF_Server {
                result: version_6::CMD_AUTH_LOGON_PROOF_Server_LoginResult::Success {
                    server_proof: proof,
                    hardware_survey_id: 0,
                    unknown: 0,
                },
            }
            .write(stream)?;
        }
        ProtocolVersion::Seven => {
            version_7::CMD_AUTH_LOGON_PROOF_Server {
                result: version_7::CMD_AUTH_LOGON_PROOF_Server_LoginResult::Success {
                    server_proof: proof,
                    hardware_survey_id: 0,
                    unknown: 0,
                },
            }
            .write(stream)?;
        }
        ProtocolVersion::Eight => {
            version_8::CMD_AUTH_LOGON_PROOF_Server {
                result: version_8::CMD_AUTH_LOGON_PROOF_Server_LoginResult::Success {
                    account_flag: version_8::AccountFlag::empty(),
                    server_proof: proof,
                    hardware_survey_id: 0,
                    unknown: 0,
                },
            }
            .write(stream)?;
        }
    }

    info!("[AUTH] '{}' Sent Logon Proof", username);

    Ok(())
}

pub(crate) fn send_cmd_auth_reconnect_challenge(
    stream: &mut TcpStream,
    protocol_version: ProtocolVersion,
    server_reconnect_challenge_data: [u8; RECONNECT_CHALLENGE_DATA_LENGTH as usize],
) -> io::Result<()> {
    match protocol_version {
        ProtocolVersion::Two => {
            version_2::CMD_AUTH_RECONNECT_CHALLENGE_Server {
                result: version_2::CMD_AUTH_RECONNECT_CHALLENGE_Server_LoginResult::Success {
                    challenge_data: server_reconnect_challenge_data,
                    checksum_salt: [0; 16],
                },
            }
            .write(stream)?;
        }
        ProtocolVersion::Five => {
            version_5::CMD_AUTH_RECONNECT_CHALLENGE_Server {
                result: version_5::CMD_AUTH_RECONNECT_CHALLENGE_Server_LoginResult::Success {
                    challenge_data: server_reconnect_challenge_data,
                    checksum_salt: [0; 16],
                },
            }
            .write(stream)?;
        }
        ProtocolVersion::Six => {
            version_6::CMD_AUTH_RECONNECT_CHALLENGE_Server {
                result: version_6::CMD_AUTH_RECONNECT_CHALLENGE_Server_LoginResult::Success {
                    challenge_data: server_reconnect_challenge_data,
                    checksum_salt: [0; 16],
                },
            }
            .write(stream)?;
        }
        ProtocolVersion::Seven => {
            version_7::CMD_AUTH_RECONNECT_CHALLENGE_Server {
                result: version_7::CMD_AUTH_RECONNECT_CHALLENGE_Server_LoginResult::Success {
                    challenge_data: server_reconnect_challenge_data,
                    checksum_salt: [0; 16],
                },
            }
            .write(stream)?;
        }
        ProtocolVersion::Eight => {
            version_8::CMD_AUTH_RECONNECT_CHALLENGE_Server {
                result: version_8::CMD_AUTH_RECONNECT_CHALLENGE_Server_LoginResult::Success {
                    challenge_data: server_reconnect_challenge_data,
                    checksum_salt: [0; 16],
                },
            }
            .write(stream)?;
        }
        ProtocolVersion::Three => panic!(),
    }

    Ok(())
}

pub(crate) fn get_cmd_auth_reconnect_proof(
    stream: &mut TcpStream,
    protocol_version: ProtocolVersion,
) -> io::Result<(
    [u8; RECONNECT_CHALLENGE_DATA_LENGTH as usize],
    [u8; PROOF_LENGTH as usize],
)> {
    match protocol_version {
        ProtocolVersion::Two => {
            let l = match expect_client_message::<version_2::CMD_AUTH_RECONNECT_PROOF_Client, _>(
                stream,
            ) {
                Ok(l) => l,
                Err(_) => {
                    return Err(io::Error::new(io::ErrorKind::Other, "error"));
                }
            };

            Ok((l.proof_data, l.client_proof))
        }
        ProtocolVersion::Five => {
            let l = match expect_client_message::<version_5::CMD_AUTH_RECONNECT_PROOF_Client, _>(
                stream,
            ) {
                Ok(l) => l,
                Err(_) => {
                    return Err(io::Error::new(io::ErrorKind::Other, "error"));
                }
            };

            Ok((l.proof_data, l.client_proof))
        }
        ProtocolVersion::Six => {
            let l = match expect_client_message::<version_6::CMD_AUTH_RECONNECT_PROOF_Client, _>(
                stream,
            ) {
                Ok(l) => l,
                Err(_) => {
                    return Err(io::Error::new(io::ErrorKind::Other, "error"));
                }
            };

            Ok((l.proof_data, l.client_proof))
        }
        ProtocolVersion::Seven => {
            let l = match expect_client_message::<version_7::CMD_AUTH_RECONNECT_PROOF_Client, _>(
                stream,
            ) {
                Ok(l) => l,
                Err(_) => {
                    return Err(io::Error::new(io::ErrorKind::Other, "error"));
                }
            };

            Ok((l.proof_data, l.client_proof))
        }
        ProtocolVersion::Eight => {
            let l = match expect_client_message::<version_8::CMD_AUTH_RECONNECT_PROOF_Client, _>(
                stream,
            ) {
                Ok(l) => l,
                Err(_) => {
                    return Err(io::Error::new(io::ErrorKind::Other, "error"));
                }
            };

            Ok((l.proof_data, l.client_proof))
        }
        ProtocolVersion::Three => panic!(),
    }
}

pub(crate) fn send_cmd_auth_reconnect_proof_success(
    stream: &mut TcpStream,
    protocol_version: ProtocolVersion,
) -> io::Result<()> {
    match protocol_version {
        ProtocolVersion::Two => version_2::CMD_AUTH_RECONNECT_PROOF_Server {
            result: version_2::LoginResult::Success,
        }
        .write(stream),
        ProtocolVersion::Five => version_5::CMD_AUTH_RECONNECT_PROOF_Server {
            result: version_5::LoginResult::Success,
        }
        .write(stream),
        ProtocolVersion::Six => version_6::CMD_AUTH_RECONNECT_PROOF_Server {
            result: version_6::LoginResult::Success,
        }
        .write(stream),
        ProtocolVersion::Seven => version_7::CMD_AUTH_RECONNECT_PROOF_Server {
            result: version_7::LoginResult::Success,
        }
        .write(stream),
        ProtocolVersion::Eight => version_8::CMD_AUTH_RECONNECT_PROOF_Server {
            result: version_8::LoginResult::Success,
        }
        .write(stream),
        ProtocolVersion::Three => panic!(),
    }
}

pub(crate) fn send_cmd_auth_reconnect_proof_incorrect_password(
    stream: &mut TcpStream,
    protocol_version: ProtocolVersion,
) -> io::Result<()> {
    match protocol_version {
        ProtocolVersion::Two => version_2::CMD_AUTH_RECONNECT_PROOF_Server {
            result: version_2::LoginResult::FailIncorrectPassword,
        }
        .write(stream),
        ProtocolVersion::Five => version_5::CMD_AUTH_RECONNECT_PROOF_Server {
            result: version_5::LoginResult::FailIncorrectPassword,
        }
        .write(stream),
        ProtocolVersion::Six => version_6::CMD_AUTH_RECONNECT_PROOF_Server {
            result: version_6::LoginResult::FailIncorrectPassword,
        }
        .write(stream),
        ProtocolVersion::Seven => version_7::CMD_AUTH_RECONNECT_PROOF_Server {
            result: version_7::LoginResult::FailIncorrectPassword,
        }
        .write(stream),
        ProtocolVersion::Eight => version_8::CMD_AUTH_RECONNECT_PROOF_Server {
            result: version_8::LoginResult::FailIncorrectPassword,
        }
        .write(stream),
        ProtocolVersion::Three => panic!(),
    }
}
