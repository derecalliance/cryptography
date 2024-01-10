/*
 * Copyright (c) DeRec Alliance and its Contributors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

use std::fmt;
use std::str::FromStr;

/// An invalid email address was encountered
#[derive(Debug, thiserror::Error)]
#[error("Invalid email address: {message} ({addr})")]
pub struct InvalidEmailError {
    message: String,
    addr: String,
}

/// Very simple email address wrapper.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct EmailAddress {
    pub local: String,
    pub domain: String,
}

#[allow(dead_code)]
impl EmailAddress {
    pub fn new(input: &str) -> Result<Self, InvalidEmailError> {
        input.parse::<EmailAddress>()
    }
}

impl fmt::Display for EmailAddress {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}@{}", self.local, self.domain)
    }
}

impl FromStr for EmailAddress {
    type Err = InvalidEmailError;

    /// Performs a dead-simple parse of an email address.
    fn from_str(input: &str) -> Result<EmailAddress, InvalidEmailError> {
        let err = |msg: &str| {
            Err(InvalidEmailError {
                message: msg.to_string(),
                addr: input.to_string(),
            })
        };
        if input.is_empty() {
            return err("empty string is not valid");
        }
        let parts: Vec<&str> = input.rsplitn(2, '@').collect();

        if input
            .chars()
            .any(|c| c.is_whitespace() || c == '<' || c == '>')
        {
            return err("Email must not contain whitespaces, '>' or '<'");
        }

        match &parts[..] {
            [domain, local] => {
                if local.is_empty() {
                    return err("empty string is not valid for local part");
                }
                if domain.is_empty() {
                    return err("missing domain after '@'");
                }
                Ok(EmailAddress {
                    local: (*local).to_string(),
                    domain: (*domain).to_string(),
                })
            }
            _ => err("missing '@' character"),
        }
    }
}
