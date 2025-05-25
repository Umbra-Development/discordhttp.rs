use rquest::EmulationProvider;
use spoofer::{client::SpoofedClient, types::HttpRequest};

pub trait DiscordHTTP {
    fn client(&self) -> SpoofedClient;
    
    async fn send_request(&self, request: HttpRequest) -> Result<rquest::Response, rquest::Error> {
        self.client().send_request(request).await
    }
}

#[derive(Debug)]
pub struct User {
    token: String,
    client: SpoofedClient,
}

impl DiscordHTTP for User {
    fn client(&self) -> SpoofedClient {
        self.client.clone()
    }

}

impl User {
    pub fn new(token: impl Into<String>, emulation: Option<EmulationProvider>) -> Self {
        Self {
            token: token.into(),
            client: SpoofedClient::new("https://canary.discord.com/api/v9", emulation) }
    }
}


#[derive(Debug)]
pub struct MultiUser {
    leader_token: String,
    tokens: Vec<String>,
    client: SpoofedClient,
}

impl DiscordHTTP for MultiUser {
    fn client(&self) -> SpoofedClient {
        self.client.clone()
    }
}


impl MultiUser {
    pub fn new(
        leader_token: impl Into<String>,
        tokens: Vec<&str>,
        emulation: Option<EmulationProvider>,
    ) -> Self {
        Self {
            leader_token: leader_token.into(),
            tokens: tokens.iter().map(|x| x.to_string()).collect(),
            client: SpoofedClient::new("https://canary.discord.com/api/v9", emulation)
        }
    }
    pub fn tokens(&self) -> Vec<String> {
        self.tokens.clone()
    }
}

pub enum DiscordClient {
    User(User),
    MultiUser(MultiUser),
}

impl DiscordClient {

    pub fn token(&self) -> String {
        match self {
            DiscordClient::User(u) => u.token.clone(),
            DiscordClient::MultiUser(u) => u.leader_token.clone(),
        }
    }

    pub async fn send_request(&self, request: HttpRequest) -> Result<rquest::Response, rquest::Error> {
        match self {
            DiscordClient::MultiUser(u) => u.send_request(request).await,
            DiscordClient::User(u) => u.send_request(request).await
        }
    }
}
