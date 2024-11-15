use crate::types::HttpRequest;
use crate::utils::{configure_proxy, decode, default_headers, encode, experiment_headers, http_default_headers, merge_headermaps, ZlibStreamDecompressor};
use crate::{easy_headers, easy_params};
use base64::alphabet::URL_SAFE;
use flate2::write::{GzEncoder, ZlibEncoder};
use rquest::tls::chrome::{http2_template_3, tls_template_6};

use rquest::tls::{Impersonate, ImpersonateSettings};
use rquest::{
    header::{HeaderMap, HeaderName, HeaderValue},
    Response,
};
use std::error::Error;
use std::io::{Read, Write};
use futures_util::StreamExt;
use serde_json::{Value, from_str, json};
pub type Client = DiscordClient;

#[derive(Debug, Clone)]
pub struct DiscordClient {
    pub client: rquest::Client,
    pub proxy_info: Option<url::Url>,
}

impl DiscordClient {
    pub async fn new(proxy: Option<rquest::Proxy>, headers: Option<&HeaderMap>) -> DiscordClient {
        let mut real_headers = default_headers(None);

        if headers.is_some() {
            merge_headermaps(&mut real_headers, headers.unwrap().clone());
        }

        let other_headers = experiment_headers(
            rquest::Client::builder()
                .impersonate_without_headers(Impersonate::Chrome128)
                .build()
                .unwrap(),
        ).await;

        merge_headermaps(&mut real_headers, other_headers);
        let mut tls_settings = tls_template_6().unwrap();
        // Pre enabled by lib - Permute Extensions, Shared key, ECH Grease
        
        tls_settings.enable_ech_grease = false;
        tls_settings.grease_enabled = Some(false);
        tls_settings.enable_signed_cert_timestamps = true;

        let impersonate = ImpersonateSettings::builder()
            .tls(tls_settings)
            .http2(http2_template_3())
            .headers(Box::new(http_default_headers))
            .build();

        let builder = rquest::Client::builder()
            .default_headers(real_headers)
            .cookie_store(true)
            .use_preconfigured_tls(impersonate);

        let client = configure_proxy(builder, proxy).build().unwrap();

        Self {
            client,
            proxy_info: None,
        }
    }
}


impl DiscordClient {
    pub async fn send_request(&self, request: HttpRequest) -> Result<Response, Box<dyn Error>> {
        let builder = request.to_request_builder(&self.client);

        let response = builder.send().await?;
        Ok(response)
    }

    pub async fn send_base_request(&self, url: &str, additional_headers: HeaderMap<HeaderValue>) {
        let client = self
            .client
            .get(url)
            .headers(additional_headers)
            .send()
            .await
            .unwrap();
        println!("{}", client.text().await.unwrap());
    }
}

#[tokio::test]
async fn get_headers() {
    let client = DiscordClient::new(None, None).await;
    for _i in 0..10 {
        client
            .send_base_request("https://httpbin.org/headers", easy_headers!({"fake": "tA"}))
            .await;
    }
}

#[tokio::test]
async fn join_server_base() {
    let invite = "Er697KFQ";
    let mut tokens = String::new();
    let mut file = std::fs::File::open("./tokens.txt").unwrap();
    file.read_to_string(&mut tokens).unwrap();
    let toks = tokens
        .lines()
        .take(5)
        .map(|s| s.to_string())
        .collect::<Vec<String>>();
    
    let client = DiscordClient::new(None, None).await;
    let resp1 = client.send_request(HttpRequest::Get {
        endpoint: format!("/invites/{}", invite),
        params: Some(easy_params!({"with_counts": "true", "with_expiration": "true"})),
        additional_headers: Some(easy_headers!({"authorization": toks.get(0).unwrap()})),
    });
    let resp = resp1.await.unwrap();
    let text = resp.text().await.unwrap();
    let val = from_str::<Value>(&text).unwrap();

    let context_json = json!({
        "location": "Invite Button Embed",
        "location_message_id": "1305101487994572842",
        "location_guild_id": val["guild"]["id"],
        "location_channel_id": val["channel"]["id"],
        "location_channel_type": val["channel"]["type"],
        
    });
    let x_context_properties = encode(&serde_json::to_string(&context_json).unwrap());
    
    for val in toks {
        
        if let Ok(resp) = client
            .send_request(HttpRequest::Post {
                endpoint: format!("/invites/{}", invite),
                body: Some(json!({"session_id": null})),
                additional_headers: Some(easy_headers!({"authorization": val, "x-context-properties": x_context_properties})),
            })
            .await {
            if resp.status().is_success() {
                println!("Token: {val}\nSuccess\n{}", resp.text().await.unwrap());
            } 
        }


    }


}


#[tokio::test]
async fn token_join_server() {
    const AMT: usize = 5;
    const COOKIE: &'static str = "__dcfduid=0fcd91109d6611efae1ed79521365559; __sdcfduid=0fcd91119d6611efae1ed795213655598b948d3c4e7cc578aa33251431ebc69b61df95127d38dc547a44bc7473fee752; __cfruid=cd2fa6e43b05469121ae898f6ef1457336b61207-1731024714; _cfuvid=h6nmMqwDnSIhr4XXd8ff1xcx7Ja65elMtqugXC7Zd0Y-1731024714918-0.0.1.1-604800000; cf_clearance=goRmXw7HX3pV5vRIF0od.CU3GwuWF4.pZkSsRjXsRsc-1731024718-1.2.1.1-D8grOksTchA3sE9BLDIR4x7_oseYuBdfxTzVV1urGqa.DvNspCj0wn.nwKEFVR7K8KeohAg1GftGL1rOEN.PDmV4H9Gm47ygEVl7rji7Pv7ww2WZ4l.hxZQl4TjZAonXR6yj.pUaWNsW7UfCMP5UlaJhpgwLB2JFCLoNR8d9RAWkgkq0bPn9A3ScI6s6FZtzB6JJdVavs1tR19CatbXr8om.m2OF0hrzkx9x9DqauYZp5X29eXkQfLJsIBYcjAC.KAn6siozTPjTMs9qiJd9OROkXE81SPEyd4N4h4mjScXESw3TIQbqbK4KJI2MPG1vsqi0rghyHA7tRRMAI2mhuVF3ijfsHpx41cwbgceoJzzL9ecD1aWQuq_HvNnRGTXb";
    const INVITE: &str = "Er697KFQ";

    let mut tokens = String::new();
    let mut auth_tokens = String::new();
    let mut file = std::fs::File::open("./tokens.txt").unwrap();
    let mut file1 = std::fs::File::open("./auth_tokens.txt").unwrap();
    file.read_to_string(&mut tokens).unwrap();
    let toks = tokens
        .lines()
        .take(AMT)
        .map(|s| s.to_string())
        .collect::<Vec<String>>();

    file1.read_to_string(&mut auth_tokens).unwrap();
    let auth_toks = auth_tokens
        .split('\n')
        .take(AMT)
        .map(|s| s.to_string())
        .collect::<Vec<String>>();

    let mut setup_headers = easy_headers!({
        "accept": "*/*",
        "accept-language": "en-US,en;q=0.9,en;q=0.8",
        "accept-encoding": "identity",
        "authorization": "OTg0OTIzMjA5OTQ0MTQxODk1.GWrcAL.3LhmVD4BPifESkJh13EM_MFjwwZ4a-i2DR-MTk",
        "cache-control": "no-cache",
        "content-type": "application/json",
        "cookie": "__dcfduid=9ab63310802211efb36681ec1e72c3d0; __sdcfduid=9ab63311802211efb36681ec1e72c3d09089d4a48b133a369cd0b3c4339e04330862368525f5de3e7bdba7abaabfc784; __stripe_mid=f3076c3e-dd56-4514-ad52-9ab3be9ba0dfd1ab73; __cfruid=3fccae3f9c418e9e267149d53d07ab3887a4917e-1731230638; _cfuvid=Uw2ux6MijdoXibNOTtchYuhDSVx4bnxsR4zsnBDpn00-1731230638918-0.0.1.1-604800000; cf_clearance=kIkVL3ZhpceNQrO13j8KXxPbIzSD8TVQuWYC0wOv394-1731230640-1.2.1.1-CiUhEN205.bM4Y3hkePZA7yMePRoS.4Rulyag3D7PDGtmEPNvB_q678ktEnZu2HStMnUM5kcBLiADCE2siVVUAw.OVsFogDbqADZ8YnSE2UA.lxm99PUda0oUlSONhJs01m2Bkm6Cgh0j.q_cNwiAZ_Cr5eTq3Lxd1kPW3emB2WPyPSHh.s_QvAdvL9mlw7_3nf4wPuyMIJbwSx9p7crU.msMaZe49ab9HicYkRCgcXDuec8RazYP9gzfc7A6b4Bd9HkYuDRsRjbVayIGXFFEx9rPoB.iXsTnJ2lpJhbKz44GTXTj7kKitZ8Y4NadEzj.igjzqdRF_I00hYXvGYwT7whOIOMQC4sbrOHogORHf2Axk3LJQ5KzFwWAFyBXNN7ob8hluYulBpN3c.nUulr9i2_T8ZLaZmvj1gFLehN4aM",
        "origin": "https://discord.com",
        "pragma": "no-cache",
        "priority": "u=1, i",
        "referer": "https://discord.com/channels/1305092234730803371/1305092235267936288",
        "sec-ch-ua": "\"Not;A=Brand\";v=\"24\", \"Chromium\";v=\"128\"",
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": "\"Linux\"",
        "sec-fetch-dest": "empty",
        "sec-fetch-mode": "cors",
        "sec-fetch-site": "same-origin",
        "user-agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) discord/0.0.71 Chrome/128.0.6613.36 Electron/32.0.0 Safari/537.36",
        "x-context-properties": "eyJsb2NhdGlvbiI6Ikludml0ZSBCdXR0b24gRW1iZWQiLCJsb2NhdGlvbl9ndWlsZF9pZCI6IjEzMDUwOTIyMzQ3MzA4MDMzNzEiLCJsb2NhdGlvbl9jaGFubmVsX2lkIjoiMTMwNTA5MjIzNTI2NzkzNjI4OCIsImxvY2F0aW9uX2NoYW5uZWxfdHlwZSI6MCwibG9jYXRpb25fbWVzc2FnZV9pZCI6IjEzMDUxMDExNjc3NDcxNDE3MjUifQ==",
        "x-debug-options": "bugReporterEnabled",
        "x-discord-locale": "en-US",
        "x-discord-timezone": "America/New_York",
        "x-super-properties": "eyJvcyI6IkxpbnV4IiwiYnJvd3NlciI6IkRpc2NvcmQgQ2xpZW50IiwicmVsZWFzZV9jaGFubmVsIjoic3RhYmxlIiwiY2xpZW50X3ZlcnNpb24iOiIwLjAuNzEiLCJvc192ZXJzaW9uIjoiNi4xLjExMi0xLU1BTkpBUk8iLCJvc19hcmNoIjoieDY0IiwiYXBwX2FyY2giOiJ4NjQiLCJzeXN0ZW1fbG9jYWxlIjoiZW4tVVMiLCJicm93c2VyX3VzZXJfYWdlbnQiOiJNb3ppbGxhLzUuMCAoWDExOyBMaW51eCB4ODZfNjQpIEFwcGxlV2ViS2l0LzUzNy4zNiAoS0hUTUwsIGxpa2UgR2Vja28pIGRpc2NvcmQvMC4wLjcxIENocm9tZS8xMjguMC42NjEzLjM2IEVsZWN0cm9uLzMyLjAuMCBTYWZhcmkvNTM3LjM2IiwiYnJvd3Nlcl92ZXJzaW9uIjoiMzIuMC4wIiwid2luZG93X21hbmFnZXIiOiJLREUsdW5rbm93biIsImRpc3RybyI6IlwiTWFuamFybyBMaW51eFwiIiwiY2xpZW50X2J1aWxkX251bWJlciI6MzQyOTY4LCJuYXRpdmVfYnVpbGRfbnVtYmVyIjpudWxsLCJjbGllbnRfZXZlbnRfc291cmNlIjpudWxsfQ=="
    });
    
    
    // easy_headers!({
    //     "accept": "*/*",
    //     "accept-language": "en-US",
    //     "Accept-Encoding": "identity", // needed to not get gzip content
    //     "content-type": "application/json",
    //     "cookie": COOKIE,
    //     "priority": "u=1, i",
    //     "referer": "https://canary.discord.com/channels/@me/1295535782525796382",
    //     "sec-ch-ua": "\"Not/A)Brand\";v=\"8\", \"Chromium\";v=\"126\"",
    //     "sec-ch-ua-mobile": "?0",
    //     "sec-ch-ua-platform": "\"Linux\"",
    //     "sec-fetch-dest": "empty",
    //     "sec-fetch-mode": "cors",
    //     "sec-fetch-site": "same-origin",
    //     "user-agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    //     "x-debug-options": "bugReporterEnabled",
    //     "x-discord-locale": "en-US",
    //     "x-discord-timezone": "America/New_York",
    //     "x-super-properties": "eyJvcyI6IkxpbnV4IiwiYnJvd3NlciI6IkNocm9tZSIsImRldmljZSI6IiIsInN5c3RlbV9sb2NhbGUiOiJlbi1VUyIsImJyb3dzZXJfdXNlcl9hZ2VudCI6Ik1vemlsbGEvNS4wIChYMTE7IExpbnV4IHg4Nl82NCkgQXBwbGVXZWJLaXQvNTM3LjM2IChLSFRNTCwgbGlrZSBHZWNrbykgQ2hyb21lLzEyNi4wLjAuMCBTYWZhcmkvNTM3LjM2IiwiYnJvd3Nlcl92ZXJzaW9uIjoiMTI2LjAuMC4wIiwib3NfdmVyc2lvbiI6IiIsInJlZmVycmVyIjoiIiwicmVmZXJyaW5nX2RvbWFpbiI6IiIsInJlZmVycmVyX2N1cnJlbnQiOiIiLCJyZWZlcnJpbmdfZG9tYWluX2N1cnJlbnQiOiIiLCJyZWxlYXNlX2NoYW5uZWwiOiJjYW5hcnkiLCJjbGllbnRfYnVpbGRfbnVtYmVyIjozNDE5NjYsImNsaWVudF9ldmVudF9zb3VyY2UiOm51bGx9"
    // });

    let client = DiscordClient::new(None, Some(&setup_headers)).await;

    let tmp = auth_toks.iter().next().unwrap();

    let mut tmp_headers = setup_headers.clone();
    tmp_headers.insert("authorization", tmp.parse().unwrap());

    let resp1 = client.send_request(HttpRequest::Get {
        endpoint: format!("/invites/{}", INVITE),
        params: Some(easy_params!({"with_counts": "true", "with_expiration": "true"})),
        additional_headers: Some(tmp_headers),
    });

    let resp = resp1.await.unwrap();
    let text = resp.text().await.unwrap();
    println!("{}", text);
    let val = from_str::<Value>(&text).unwrap();

    let context_json = json!({
        "location": "Invite Button Embed",
        "location_message_id": "1305101487994572842",
        "location_guild_id": val["guild"]["id"],
        "location_channel_id": val["channel"]["id"],
        "location_channel_type": val["channel"]["type"],
        
    });

    let x_context_properties = encode(&serde_json::to_string(&context_json).unwrap());

    setup_headers.insert(
        "x-context-properties",
        // HeaderValue::from_static("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJsb2NhdGlvbiI6Ikludml0ZSBCdXR0b24gRW1iZWQiLCJsb2NhdGlvbl9ndWlsZF9pZCI6IjEyOTk3ODA3NzYwOTQ1OTcxODEiLCJsb2NhdGlvbl9jaGFubmVsX2lkIjoiMTMwMDU3ODU0MzkyNjkwMjg2OCIsImxvY2F0aW9uX2NoYW5uZWxfdHlwZSI6InRleHQiLCJsb2NhdGlvbl9tZXNzYWdlX2lkIjoiMTMwNDU5OTk5OTAwNjUxMTE4NSJ9.7x_3sToAZ5hqXLtpMPCkzsh9VJ2CqK6HiEVz82HkRRA")
        HeaderValue::from_str(&x_context_properties).unwrap(),
    );

    'outer: for val in toks {
            let client = client.clone();
            let setup_headers = setup_headers.clone();
            let invite = INVITE.to_string();
            // task::spawn(async move {
                let mut headers = setup_headers.clone();
                headers.insert("authorization", val.parse().unwrap());

                // let ws_client = WebsocketClient::builder()
                //     .token(&val)
                //     .connect(Some(setup_headers.clone()))
                //     .await;

                // for _i in 0..10 {
                //     if ws_client.closed().await {
                //         continue 'outer; // skip invalid token
                //     }
                //     if ws_client.ready().await {
                //         break;
                //     }
                //     tokio::time::sleep(Duration::from_secs(1)).await;
                // }

                // let session_id = ws_client.session_id().await.unwrap();

                // Join the server
                let resp = client
                    .send_request(HttpRequest::Post {
                        endpoint: format!("/invites/{}", invite),
                        body: Some(json!({"session_id": null})),
                        additional_headers: Some(headers.clone()),
                    })
                    .await;

                match resp {
                    Ok(response) if response.status().is_success() => {
                        println!("Token has joined the server: {}", val);
                    }
                    Ok(response) => {
                        let resp_headers = response.headers();
                        let cookies = headers
                            .get_all("set-cookie")
                            .into_iter()
                            .map(|header_value| header_value.to_str().unwrap_or("").to_string())
                            .collect::<Vec<String>>();

                        println!(
                            "Token could not join the server: {}\n{}\n{}",
                            val,
                            response.status().as_str(),
                            response.url()
                        );
                        println!("{:?}", headers);
                        println!("{:?}", cookies);
                        println!("{}", response.text().await.unwrap());
                    }
                    Err(e) => {
                        eprintln!("Failed to send join request for token {}: {}", val, e);
                    }
                }
            // })
        }
    

    // Await all join/leave tasks
    // future::join_all(tasks).await;
}






#[tokio::test]
async fn add_bot_to_server() {
    const COOKIE: &'static str = "__dcfduid=0fcd91109d6611efae1ed79521365559; __sdcfduid=0fcd91119d6611efae1ed795213655598b948d3c4e7cc578aa33251431ebc69b61df95127d38dc547a44bc7473fee752; __cfruid=cd2fa6e43b05469121ae898f6ef1457336b61207-1731024714; _cfuvid=h6nmMqwDnSIhr4XXd8ff1xcx7Ja65elMtqugXC7Zd0Y-1731024714918-0.0.1.1-604800000; cf_clearance=goRmXw7HX3pV5vRIF0od.CU3GwuWF4.pZkSsRjXsRsc-1731024718-1.2.1.1-D8grOksTchA3sE9BLDIR4x7_oseYuBdfxTzVV1urGqa.DvNspCj0wn.nwKEFVR7K8KeohAg1GftGL1rOEN.PDmV4H9Gm47ygEVl7rji7Pv7ww2WZ4l.hxZQl4TjZAonXR6yj.pUaWNsW7UfCMP5UlaJhpgwLB2JFCLoNR8d9RAWkgkq0bPn9A3ScI6s6FZtzB6JJdVavs1tR19CatbXr8om.m2OF0hrzkx9x9DqauYZp5X29eXkQfLJsIBYcjAC.KAn6siozTPjTMs9qiJd9OROkXE81SPEyd4N4h4mjScXESw3TIQbqbK4KJI2MPG1vsqi0rghyHA7tRRMAI2mhuVF3ijfsHpx41cwbgceoJzzL9ecD1aWQuq_HvNnRGTXb";
    // const BOT_ID: &str = "1196556567403831346";
    const SERVER_ID: &str = "1305086436420358214";

    let body = json!({
        "guild_id": SERVER_ID,
        "permissions": "0",
        "authorize": true,
        "integration_type": 0,
        "location_context": {
            "guild_id": SERVER_ID,
            // "channel_id": "1299815021794164841", // apparently unneeded.
            // "channel_type": 0
        }
    });

    let mut tokens = String::new();
    let mut file = std::fs::File::open("./auth_tokens.txt").unwrap();
    file.read_to_string(&mut tokens).unwrap();
    let token = tokens.split("\n").next().expect("No tokens in file.");

    let mut file1 = std::fs::File::open("./bot_tokens.txt").unwrap();
    let mut tokens1 = String::new();

    file1.read_to_string(&mut tokens1).unwrap();
    let bot_tokens = tokens1.split("\n").collect::<Vec<&str>>();

    // get user ids from tokens
    // let tokens_and_user_ids = bot_tokens
    //     .into_iter()
    //     .map(|token| {
    //         (
    //             token,
    //             decode_user_id(token.split(".").nth(0).unwrap()).unwrap(),
    //         )
    //     })
    //     .collect::<Vec<(&str, String)>>();

    let tokens_and_user_ids = vec![
        "824119071556763668".to_string(),
        "235148962103951360".to_string(),
        "1196556567403831346".to_string(),
        "155149108183695360".to_string(),
        "499595256270946326".to_string(),
        "651095740390834176".to_string(),
        "491769129318088714".to_string(),
        "1304596191719198730".to_string(),
        "1293609771848568894".to_string(),
        "1057786019799380059".to_string(),
        "1289609657693765683".to_string(),
        "1304539950070501426".to_string(),
        "204255221017214977".to_string(),
        "703886990948565003".to_string(),
        "944016826751389717".to_string(),
        "416358583220043796".to_string(),
        "720351927581278219".to_string(),
        "172002275412279296".to_string(),
        "432533456807919639".to_string(),
        "302050872383242240".to_string(),
        "409875566800404480".to_string(),
        "153613756348366849".to_string(),
        "508391840525975553".to_string(),
        "1097266546180636863".to_string(),
        "585271178180952064".to_string(),
        "500658624109084682".to_string(),
        "755582602366287882".to_string(),
        "1140192603221020725".to_string(),
        "873934253468024852".to_string(),
        "715621848489918495".to_string(),
        "684773505157431347".to_string(),
        "356268235697553409".to_string(),
        "536991182035746816".to_string(),
        "472911936951156740".to_string(),
        "513423712582762502".to_string(),
        "692045914436796436".to_string(),
        "557628352828014614".to_string(),
        "828462865412784148".to_string(),
        "346353957029019648".to_string(),
        "458276816071950337".to_string(),
        "678344927997853742".to_string(),
        "550613223733329920".to_string(),
        "559426966151757824".to_string(),
        "575252669443211264".to_string(),
        "439205512425504771".to_string(),
        "949479338275913799".to_string(),
        "805342184748220426".to_string(),
        "423637161632464906".to_string(),
        "471091072546766849".to_string(),
        "1003836018237120512".to_string(),
        "735147814878969968".to_string(),
        "429305856241172480".to_string(),
        "746453621821931634".to_string(),
        "270904126974590976".to_string(),
        "862039253574746125".to_string(),
        "712011923176030229".to_string(),
        "512333785338216465".to_string(),
        "656621136808902656".to_string(),
        "999736048596816014".to_string(),
        "437808476106784770".to_string(),
        "853327905357561948".to_string(),
        "247283454440374274".to_string(),
    ];
    

    let setup_headers = easy_headers!({
        "accept": "*/*",
        "accept-language": "en-US",
        "Accept-Encoding": "identity", // needed to not get gzip content
        "authorization": token,
        "content-type": "application/json",
        "cookie": COOKIE,
        "priority": "u=1, i",
        // "referer": format!("https://canary.discord.com/channels/{}/{}", body["guild_id"], body["location_context"]["channel_id"]),
        "sec-ch-ua": "\"Not/A)Brand\";v=\"8\", \"Chromium\";v=\"126\"",
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": "\"Linux\"",
        "sec-fetch-dest": "empty",
        "sec-fetch-mode": "cors",
        "sec-fetch-site": "same-origin",
        "user-agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
        "x-debug-options": "bugReporterEnabled",
        "x-discord-locale": "en-US",
        "x-discord-timezone": "America/New_York",
        "x-super-properties": "eyJvcyI6IkxpbnV4IiwiYnJvd3NlciI6IkNocm9tZSIsImRldmljZSI6IiIsInN5c3RlbV9sb2NhbGUiOiJlbi1VUyIsImJyb3dzZXJfdXNlcl9hZ2VudCI6Ik1vemlsbGEvNS4wIChYMTE7IExpbnV4IHg4Nl82NCkgQXBwbGVXZWJLaXQvNTM3LjM2IChLSFRNTCwgbGlrZSBHZWNrbykgQ2hyb21lLzEyNi4wLjAuMCBTYWZhcmkvNTM3LjM2IiwiYnJvd3Nlcl92ZXJzaW9uIjoiMTI2LjAuMC4wIiwib3NfdmVyc2lvbiI6IiIsInJlZmVycmVyIjoiIiwicmVmZXJyaW5nX2RvbWFpbiI6IiIsInJlZmVycmVyX2N1cnJlbnQiOiIiLCJyZWZlcnJpbmdfZG9tYWluX2N1cnJlbnQiOiIiLCJyZWxlYXNlX2NoYW5uZWwiOiJjYW5hcnkiLCJjbGllbnRfYnVpbGRfbnVtYmVyIjozNDIwNjMsImNsaWVudF9ldmVudF9zb3VyY2UiOm51bGx9"
    });

    use tokio::task;
    use tokio::try_join;

    futures::stream::iter(tokens_and_user_ids)
        .for_each_concurrent(None, |user_id| {
            let body = body.clone();
            let headers = setup_headers.clone();

            // Spawning each request as an async task
            async move {
                let client = DiscordClient::new(None, Some(&headers)).await;

                // Adding a bot
                let resp = client
                    .send_request(HttpRequest::Post {
                        endpoint: format!(
                            "/oauth2/authorize?client_id={}&scope=bot%20applications.commands",
                            user_id
                        ),
                        body: Some(body),
                        additional_headers: Some(headers),
                    })
                    .await;

                match resp {
                    Ok(response) => {
                        println!("{}", response.status().as_str());
                        if response.status().is_success() {
                            println!("Token has joined the server");
                            println!("{}", response.text().await.unwrap());
                        } else {
                            let headers = response.headers();
                            let cookies = headers
                                .get_all("set-cookie")
                                .into_iter()
                                .map(|header_value| header_value.to_str().unwrap_or("").to_string())
                                .collect::<Vec<String>>();

                            println!(
                                "Token could not join the server: \n{}\n{}",
                                response.status().as_str(),
                                response.url()
                            );
                            println!("{:?}", headers);
                            println!("{:?}", cookies);
                            println!("{}", response.text().await.unwrap());
                        }
                    }
                    Err(e) => {
                        println!("Request failed: {:?}", e);
                    }
                }
            }
        })
        .await;
}


#[tokio::test]
async fn create_discord_application() {
    const COOKIE: &str = "__dcfduid=0fcd91109d6611efae1ed79521365559; __sdcfduid=0fcd91119d6611efae1ed795213655598b948d3c4e7cc578aa33251431ebc69b61df95127d38dc547a44bc7473fee752; __cfruid=cd2fa6e43b05469121ae898f6ef1457336b61207-1731024714; _cfuvid=h6nmMqwDnSIhr4XXd8ff1xcx7Ja65elMtqugXC7Zd0Y-1731024714918-0.0.1.1-604800000; cf_clearance=goRmXw7HX3pV5vRIF0od.CU3GwuWF4.pZkSsRjXsRsc-1731024718-1.2.1.1-D8grOksTchA3sE9BLDIR4x7_oseYuBdfxTzVV1urGqa.DvNspCj0wn.nwKEFVR7K8KeohAg1GftGL1rOEN.PDmV4H9Gm47ygEVl7rji7Pv7ww2WZ4l.hxZQl4TjZAonXR6yj.pUaWNsW7UfCMP5UlaJhpgwLB2JFCLoNR8d9RAWkgkq0bPn9A3ScI6s6FZtzB6JJdVavs1tR19CatbXr8om.m2OF0hrzkx9x9DqauYZp5X29eXkQfLJsIBYcjAC.KAn6siozTPjTMs9qiJd9OROkXE81SPEyd4N4h4mjScXESw3TIQbqbK4KJI2MPG1vsqi0rghyHA7tRRMAI2mhuVF3ijfsHpx41cwbgceoJzzL9ecD1aWQuq_HvNnRGTXb";
    const NAMES: [&str; 1] = ["Test Application"];

    let mut tokens = String::new();
    let mut file = std::fs::File::open("./auth_tokens.txt").unwrap();
    file.read_to_string(&mut tokens).unwrap();
    let token = tokens.split("\n").next().expect("No tokens in file.");
  
    let setup_headers = easy_headers!({
       "accept": "*/*",
       "accept-language": "en-US",
       "Accept-Encoding": "identity", // needed to not get gzip content
       "content-type": "application/json",
       "cookie": COOKIE,
       "priority": "u=1, i",
       // "referer": format!("https://canary.discord.com/channels/{}/{}", body["guild_id"], body["location_context"]["channel_id"]),
       "sec-ch-ua": "\"Not/A)Brand\";v=\"8\", \"Chromium\";v=\"126\"",
       "sec-ch-ua-mobile": "?0",
       "sec-ch-ua-platform": "\"Linux\"",
       "sec-fetch-dest": "empty",
       "sec-fetch-mode": "cors",
       "sec-fetch-site": "same-origin",
       "user-agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
       "x-debug-options": "bugReporterEnabled",
       "x-discord-locale": "en-US",
       "x-discord-timezone": "America/New_York",
       "x-track": "eyJvcyI6IkxpbnV4IiwiYnJvd3NlciI6IkNocm9tZSIsImRldmljZSI6IiIsInN5c3RlbV9sb2NhbGUiOiJlbi1VUyIsImJyb3dzZXJfdXNlcl9hZ2VudCI6Ik1vemlsbGEvNS4wIChYMTE7IExpbnV4IHg4Nl82NCkgQXBwbGVXZWJLaXQvNTM3LjM2IChLSFRNTCwgbGlrZSBHZWNrbykgQ2hyb21lLzEyNi4wLjAuMCBTYWZhcmkvNTM3LjM2IiwiYnJvd3Nlcl92ZXJzaW9uIjoiMTI2LjAuMC4wIiwib3NfdmVyc2lvbiI6IiIsInJlZmVycmVyIjoiIiwicmVmZXJyaW5nX2RvbWFpbiI6IiIsInJlZmVycmVyX2N1cnJlbnQiOiIiLCJyZWZlcnJpbmdfZG9tYWluX2N1cnJlbnQiOiIiLCJyZWxlYXNlX2NoYW5uZWwiOiJjYW5hcnkiLCJjbGllbnRfYnVpbGRfbnVtYmVyIjozNDIwNjMsImNsaWVudF9ldmVudF9zb3VyY2UiOm51bGx9"
    });
 
    let client = DiscordClient::new(None, Some(&setup_headers)).await;

    for val in NAMES.iter() {
        let target = json!({"name": val, "team_id": null});

        let mut headers = setup_headers.clone();
        headers.insert("authorization", HeaderValue::from_str(token).unwrap());

        let resp = client.send_request(HttpRequest::Post {
            endpoint: "/applications".to_string(),
            body: Some(target),
            additional_headers: Some(headers),
        });

        let resp = resp.await.unwrap();

        println!("{}", resp.status().as_str());

        match resp.status().as_u16() {
            201 => {
                println!("Success! {}", resp.text().await.unwrap());
            }
            err => {
                println!("Issue: {} {}", err, resp.text().await.unwrap());
            }
        }
    }
}

#[tokio::test]
async fn friend_request_user() {
    const USERNAME: &str = "gen6442";
    const COOKIE: &str = "__dcfduid=0fcd91109d6611efae1ed79521365559; __sdcfduid=0fcd91119d6611efae1ed795213655598b948d3c4e7cc578aa33251431ebc69b61df95127d38dc547a44bc7473fee752; __cfruid=cd2fa6e43b05469121ae898f6ef1457336b61207-1731024714; _cfuvid=h6nmMqwDnSIhr4XXd8ff1xcx7Ja65elMtqugXC7Zd0Y-1731024714918-0.0.1.1-604800000; cf_clearance=goRmXw7HX3pV5vRIF0od.CU3GwuWF4.pZkSsRjXsRsc-1731024718-1.2.1.1-D8grOksTchA3sE9BLDIR4x7_oseYuBdfxTzVV1urGqa.DvNspCj0wn.nwKEFVR7K8KeohAg1GftGL1rOEN.PDmV4H9Gm47ygEVl7rji7Pv7ww2WZ4l.hxZQl4TjZAonXR6yj.pUaWNsW7UfCMP5UlaJhpgwLB2JFCLoNR8d9RAWkgkq0bPn9A3ScI6s6FZtzB6JJdVavs1tR19CatbXr8om.m2OF0hrzkx9x9DqauYZp5X29eXkQfLJsIBYcjAC.KAn6siozTPjTMs9qiJd9OROkXE81SPEyd4N4h4mjScXESw3TIQbqbK4KJI2MPG1vsqi0rghyHA7tRRMAI2mhuVF3ijfsHpx41cwbgceoJzzL9ecD1aWQuq_HvNnRGTXb";
    const AMT: usize = 1;

    let mut tokens = String::new();
    let mut file = std::fs::File::open("./tokens.txt").unwrap();
    file.read_to_string(&mut tokens).unwrap();
    let vals = tokens.split("\n").take(AMT).collect::<Vec<&str>>();

    let mut setup_headers = easy_headers!({
       "accept": "*/*",
       "accept-language": "en-US",
       "Accept-Encoding": "identity", // needed to not get gzip content
       "content-type": "application/json",
       "cookie": COOKIE,
       "priority": "u=1, i",
       // "referer": format!("https://canary.discord.com/channels/{}/{}", body["guild_id"], body["location_context"]["channel_id"]),
       "sec-ch-ua": "\"Not/A)Brand\";v=\"8\", \"Chromium\";v=\"126\"",
       "sec-ch-ua-mobile": "?0",
       "sec-ch-ua-platform": "\"Linux\"",
       "sec-fetch-dest": "empty",
       "sec-fetch-mode": "cors",
       "sec-fetch-site": "same-origin",
       "user-agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
       "x-debug-options": "bugReporterEnabled",
       "x-discord-locale": "en-US",
       "x-discord-timezone": "America/New_York",
       "x-super-properties": "eyJvcyI6IkxpbnV4IiwiYnJvd3NlciI6IkNocm9tZSIsImRldmljZSI6IiIsInN5c3RlbV9sb2NhbGUiOiJlbi1VUyIsImJyb3dzZXJfdXNlcl9hZ2VudCI6Ik1vemlsbGEvNS4wIChYMTE7IExpbnV4IHg4Nl82NCkgQXBwbGVXZWJLaXQvNTM3LjM2IChLSFRNTCwgbGlrZSBHZWNrbykgQ2hyb21lLzEyNi4wLjAuMCBTYWZhcmkvNTM3LjM2IiwiYnJvd3Nlcl92ZXJzaW9uIjoiMTI2LjAuMC4wIiwib3NfdmVyc2lvbiI6IiIsInJlZmVycmVyIjoiIiwicmVmZXJyaW5nX2RvbWFpbiI6IiIsInJlZmVycmVyX2N1cnJlbnQiOiIiLCJyZWZlcnJpbmdfZG9tYWluX2N1cnJlbnQiOiIiLCJyZWxlYXNlX2NoYW5uZWwiOiJjYW5hcnkiLCJjbGllbnRfYnVpbGRfbnVtYmVyIjozNDIwNjMsImNsaWVudF9ldmVudF9zb3VyY2UiOm51bGx9"
    });

    let context_json = json!({
        "location": "Add Friend"
    });

    let x_context_properties = base64::encode(&serde_json::to_string(&context_json).unwrap());
    setup_headers.insert(
        "x-context-properties",
        HeaderValue::from_str(&x_context_properties).unwrap(),
    );

    let target = json!({
        "username": USERNAME,
        "discriminator": null

    });

    let client = DiscordClient::new(None, Some(&setup_headers)).await;

    for val in vals {
        let mut headers = setup_headers.clone();
        headers.insert("authorization", val.parse().unwrap());

        let resp = client.send_request(HttpRequest::Post {
            endpoint: "/users/@me/relationships".to_string(),
            body: Some(target.clone()),
            additional_headers: Some(headers),
        });

        let resp = resp.await.unwrap();

        println!("{}", resp.status().as_str());

        match resp.status().as_u16() {
            204 => println!("Friend request sent to: {}", val),
            201 => println!("Friend request sent to: {}", val),
            304 => println!("Friend request already sent to: {}", val),
            400 => println!("Bad request: {}", val),
            403 => println!("Forbidden: {}", val),
            429 => println!("Rate limited: {}", val),
            500 => println!("Internal server error: {}", val),
            502 => println!("Bad gateway: {}", val),
            503 => println!("Service unavailable: {}", val),
            504 => println!("Gateway timeout: {}", val),
            _ => {
                println!("Unknown status code: {}", val);
                println!("{}", resp.text().await.unwrap());
            }
        }
    }
}

#[tokio::test]
async fn friend_request_user_alt() {
    const USER_ID: &str = "984923209944141895";
    const COOKIE: &str = "__dcfduid=0fcd91109d6611efae1ed79521365559; __sdcfduid=0fcd91119d6611efae1ed795213655598b948d3c4e7cc578aa33251431ebc69b61df95127d38dc547a44bc7473fee752; __cfruid=cd2fa6e43b05469121ae898f6ef1457336b61207-1731024714; _cfuvid=h6nmMqwDnSIhr4XXd8ff1xcx7Ja65elMtqugXC7Zd0Y-1731024714918-0.0.1.1-604800000; cf_clearance=goRmXw7HX3pV5vRIF0od.CU3GwuWF4.pZkSsRjXsRsc-1731024718-1.2.1.1-D8grOksTchA3sE9BLDIR4x7_oseYuBdfxTzVV1urGqa.DvNspCj0wn.nwKEFVR7K8KeohAg1GftGL1rOEN.PDmV4H9Gm47ygEVl7rji7Pv7ww2WZ4l.hxZQl4TjZAonXR6yj.pUaWNsW7UfCMP5UlaJhpgwLB2JFCLoNR8d9RAWkgkq0bPn9A3ScI6s6FZtzB6JJdVavs1tR19CatbXr8om.m2OF0hrzkx9x9DqauYZp5X29eXkQfLJsIBYcjAC.KAn6siozTPjTMs9qiJd9OROkXE81SPEyd4N4h4mjScXESw3TIQbqbK4KJI2MPG1vsqi0rghyHA7tRRMAI2mhuVF3ijfsHpx41cwbgceoJzzL9ecD1aWQuq_HvNnRGTXb";
    const AMT: usize = 1;

    let mut tokens = String::new();
    let mut file = std::fs::File::open("./tokens.txt").unwrap();
    file.read_to_string(&mut tokens).unwrap();
    let vals = tokens.split("\n").take(AMT).collect::<Vec<&str>>();

    let mut setup_headers = easy_headers!({
       "accept": "*/*",
       "accept-language": "en-US",
       "Accept-Encoding": "identity", // needed to not get gzip content
       "content-type": "application/json",
       "cookie": COOKIE,
       "priority": "u=1, i",
       // "referer": format!("https://canary.discord.com/channels/{}/{}", body["guild_id"], body["location_context"]["channel_id"]),
       "sec-ch-ua": "\"Not/A)Brand\";v=\"8\", \"Chromium\";v=\"126\"",
       "sec-ch-ua-mobile": "?0",
       "sec-ch-ua-platform": "\"Linux\"",
       "sec-fetch-dest": "empty",
       "sec-fetch-mode": "cors",
       "sec-fetch-site": "same-origin",
       "user-agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
       "x-debug-options": "bugReporterEnabled",
       "x-discord-locale": "en-US",
       "x-discord-timezone": "America/New_York",
       "x-super-properties": "eyJvcyI6IkxpbnV4IiwiYnJvd3NlciI6IkNocm9tZSIsImRldmljZSI6IiIsInN5c3RlbV9sb2NhbGUiOiJlbi1VUyIsImJyb3dzZXJfdXNlcl9hZ2VudCI6Ik1vemlsbGEvNS4wIChYMTE7IExpbnV4IHg4Nl82NCkgQXBwbGVXZWJLaXQvNTM3LjM2IChLSFRNTCwgbGlrZSBHZWNrbykgQ2hyb21lLzEyNi4wLjAuMCBTYWZhcmkvNTM3LjM2IiwiYnJvd3Nlcl92ZXJzaW9uIjoiMTI2LjAuMC4wIiwib3NfdmVyc2lvbiI6IiIsInJlZmVycmVyIjoiIiwicmVmZXJyaW5nX2RvbWFpbiI6IiIsInJlZmVycmVyX2N1cnJlbnQiOiIiLCJyZWZlcnJpbmdfZG9tYWluX2N1cnJlbnQiOiIiLCJyZWxlYXNlX2NoYW5uZWwiOiJjYW5hcnkiLCJjbGllbnRfYnVpbGRfbnVtYmVyIjozNDIwNjMsImNsaWVudF9ldmVudF9zb3VyY2UiOm51bGx9"
    });

    let context_json = json!({
        "location": "bite size profile popout"
    });

    let x_context_properties = base64::encode(&serde_json::to_string(&context_json).unwrap());
    setup_headers.insert(
        "x-context-properties",
        HeaderValue::from_str(&x_context_properties).unwrap(),
    );

    let target = json!({});

    let client = DiscordClient::new(None, Some(&setup_headers)).await;

    for val in vals {
        let mut headers = setup_headers.clone();
        headers.insert("authorization", val.parse().unwrap());

        let resp = client.send_request(HttpRequest::Put {
            endpoint: format!("/users/@me/relationships/{}", USER_ID),
            body: Some(target.clone()),
            additional_headers: Some(headers),
        });

        let resp = resp.await.unwrap();

        println!("{}", resp.status().as_str());

        match resp.status().as_u16() {
            204 => println!("Friend request sent to: {}", val),
            201 => println!("Friend request sent to: {}", val),
            304 => println!("Friend request already sent to: {}", val),
            400 => {
                println!("Bad request: {}", val);
                println!("{}", resp.text().await.unwrap());
            }
            403 => println!("Forbidden: {}", val),
            429 => println!("Rate limited: {}", val),
            500 => println!("Internal server error: {}", val),
            502 => println!("Bad gateway: {}", val),
            503 => println!("Service unavailable: {}", val),
            504 => println!("Gateway timeout: {}", val),
            _ => {
                println!("Unknown status code: {}", val);
                println!("{}", resp.text().await.unwrap());
            }
        }
    }
}

#[tokio::test]
async fn accept_agreements() {
    const AMT: usize = 100;
    const COOKIE: &str = "__dcfduid=0fcd91109d6611efae1ed79521365559; __sdcfduid=0fcd91119d6611efae1ed795213655598b948d3c4e7cc578aa33251431ebc69b61df95127d38dc547a44bc7473fee752; __cfruid=cd2fa6e43b05469121ae898f6ef1457336b61207-1731024714; _cfuvid=h6nmMqwDnSIhr4XXd8ff1xcx7Ja65elMtqugXC7Zd0Y-1731024714918-0.0.1.1-604800000; cf_clearance=goRmXw7HX3pV5vRIF0od.CU3GwuWF4.pZkSsRjXsRsc-1731024718-1.2.1.1-D8grOksTchA3sE9BLDIR4x7_oseYuBdfxTzVV1urGqa.DvNspCj0wn.nwKEFVR7K8KeohAg1GftGL1rOEN.PDmV4H9Gm47ygEVl7rji7Pv7ww2WZ4l.hxZQl4TjZAonXR6yj.pUaWNsW7UfCMP5UlaJhpgwLB2JFCLoNR8d9RAWkgkq0bPn9A3ScI6s6FZtzB6JJdVavs1tR19CatbXr8om.m2OF0hrzkx9x9DqauYZp5X29eXkQfLJsIBYcjAC.KAn6siozTPjTMs9qiJd9OROkXE81SPEyd4N4h4mjScXESw3TIQbqbK4KJI2MPG1vsqi0rghyHA7tRRMAI2mhuVF3ijfsHpx41cwbgceoJzzL9ecD1aWQuq_HvNnRGTXb";

    let mut token_str = String::new();
    let mut file = std::fs::File::open("./tokens.txt").unwrap();
    file.read_to_string(&mut token_str).unwrap();
    let tokens = token_str.split("\n").take(AMT).map(|s| s.to_string())
    .collect::<Vec<String>>();


    let mut setup_headers = easy_headers!({
        "accept": "*/*",
        "accept-language": "en-US",
        "Accept-Encoding": "identity", // needed to not get gzip content
        "content-type": "application/json",
        "cookie": COOKIE,
        "priority": "u=1, i",
        // "referer": format!("https://canary.discord.com/channels/{}/{}", body["guild_id"], body["location_context"]["channel_id"]),
        "sec-ch-ua": "\"Not/A)Brand\";v=\"8\", \"Chromium\";v=\"126\"",
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": "\"Linux\"",
        "sec-fetch-dest": "empty",
        "sec-fetch-mode": "cors",
        "sec-fetch-site": "same-origin",
        "user-agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
        "x-debug-options": "bugReporterEnabled",
        "x-discord-locale": "en-US",
        "x-discord-timezone": "America/New_York",
        "x-super-properties": "eyJvcyI6IkxpbnV4IiwiYnJvd3NlciI6IkNocm9tZSIsImRldmljZSI6IiIsInN5c3RlbV9sb2NhbGUiOiJlbi1VUyIsImJyb3dzZXJfdXNlcl9hZ2VudCI6Ik1vemlsbGEvNS4wIChYMTE7IExpbnV4IHg4Nl82NCkgQXBwbGVXZWJLaXQvNTM3LjM2IChLSFRNTCwgbGlrZSBHZWNrbykgQ2hyb21lLzEyNi4wLjAuMCBTYWZhcmkvNTM3LjM2IiwiYnJvd3Nlcl92ZXJzaW9uIjoiMTI2LjAuMC4wIiwib3NfdmVyc2lvbiI6IiIsInJlZmVycmVyIjoiIiwicmVmZXJyaW5nX2RvbWFpbiI6IiIsInJlZmVycmVyX2N1cnJlbnQiOiIiLCJyZWZlcnJpbmdfZG9tYWluX2N1cnJlbnQiOiIiLCJyZWxlYXNlX2NoYW5uZWwiOiJjYW5hcnkiLCJjbGllbnRfYnVpbGRfbnVtYmVyIjozNDIwNjMsImNsaWVudF9ldmVudF9zb3VyY2UiOm51bGx9"
     });


    let tasks: Vec<_> = tokens.into_iter().map(|t| {
        let setup_headers = setup_headers.clone();

        tokio::spawn(async move {
            let client = DiscordClient::new(None, Some(&setup_headers)).await;

            let mut headers = setup_headers.clone();
            headers.insert("authorization", t.parse().unwrap());

            let resp = client.send_request(HttpRequest::Patch {
                endpoint: "/users/@me/agreements".to_string(),
                body: Some(json!({"terms":true,"privacy":true})),
                additional_headers: Some(headers),
            });

            let resp = resp.await.unwrap();

            println!("{}", resp.status().as_str());

            match resp.status().as_u16() {
                204 => println!("Agreement accepted: {}", t),
                201 => println!("Agreement accepted: {}", t),
                304 => println!("Agreement already accepted: {}", t),
                400 => {
                    println!("Bad request: {}", t);
                    println!("{}", resp.text().await.unwrap());
                }
                403 => println!("Forbidden: {}", t),
                429 => println!("Rate limited: {}", t),
                500 => println!("Internal server error: {}", t),
                502 => println!("Bad gateway: {}", t),
                503 => println!("Service unavailable: {}", t),
                504 => println!("Gateway timeout: {}", t),
                _ => {
                    println!("Unknown status code: {}", t);
                    println!("{}", resp.text().await.unwrap());
                }
            }
        })



    }).collect();

    futures::future::join_all(tasks).await;
}




#[tokio::test]
async fn ja3_fingerprint_test() {
    let client = DiscordClient::new(None, None).await;
    let response = client
        .client
        .get("https://tools.scrapfly.io/api/tls")
        .send()
        .await
        .unwrap();

    println!(
        "{}",
        serde_json::to_string_pretty(&from_str::<Value>(&response.text().await.unwrap()).unwrap())
            .unwrap()
    );
}
