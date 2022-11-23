use yew::{
    prelude::*,
    events::InputEvent
};
use web_sys::HtmlInputElement;
use regex::Regex;
use wasm_logger;

pub mod encryption;

const DEFAULT_KEY: &str = "SECRET_KEY_WITH_LENGTH_32_BYTES_";

enum Msg {
    SecretKeyChange(String),
    MessageInputChange(String),
    HashInputChange(String)
}

struct Model {
    secret_key: String,
    message_input: String,
    message_hash: String,
    hash_input: String,
    encoded_message: String
}

impl Component for Model {
    type Message = Msg;
    type Properties = ();

    fn create(_ctx: &Context<Self>) -> Self {
        Self {
            secret_key: String::from(DEFAULT_KEY),
            message_input: String::new(),
            message_hash: String::new(),
            hash_input: String::new(),
            encoded_message: String::new()
        }
    }

    fn update(&mut self, _ctx: &Context<Self>, msg: Self::Message) -> bool {
        match msg {
            Msg::SecretKeyChange(secret_key) => {
                let re_hash = Regex::new(r"^[0-9\s,]+$").unwrap();

                let secret_key_bytes_len = secret_key.as_bytes().len();
                match secret_key_bytes_len {
                    32 => {
                        self.secret_key = secret_key;

                        self.message_hash = match encryption::encrypt(
                            self.message_input.as_bytes(),
                            self.secret_key.as_bytes()
                        ) {
                            Ok(hash) => {
                                let message = format!("{:?}", hash);
                                let mut chars = message.chars();
                                chars.next();
                                chars.next_back();
                                chars.as_str().to_string()
                            },
                            Err(err_message) => err_message
                        };

                        match re_hash.is_match(&self.hash_input) {
                            true => {
                                match encryption::str_to_bytes(&self.hash_input) {
                                    Ok(bytes_vec) => {
                                        self.encoded_message = match encryption::decrypt(
                                            bytes_vec.as_slice(),
                                            self.secret_key.as_bytes()
                                        ) {
                                            Ok(decrypted_message) => {
                                                match std::str::from_utf8(&decrypted_message) {
                                                    Ok(message) => message.to_string(),
                                                    Err(_) => String::from("Не удалось расшифровать сообщение")
                                                }
                                            },
                                            Err(err_message) => err_message
                                        }
                                    },
                                    Err(err_message) => {
                                        self.encoded_message = err_message
                                    }
                                }
                            },
                            false => {
                                self.hash_input = String::new();
                                self.encoded_message = String::new();
                            }
                        }
                    },
                    key_size => {
                        let message = format!("Длина ключа должна быть 32 байта. Текущая длина: {} байтов", key_size);
                        self.message_hash = message.clone();
                        self.encoded_message = message;
                    }
                }
            }
            Msg::MessageInputChange(message) => {
                self.message_input = message;
                self.message_hash = match encryption::encrypt(
                    self.message_input.as_bytes(),
                    self.secret_key.as_bytes()
                ) {
                    Ok(hash) => {
                        let message = format!("{:?}", hash);
                        let mut chars = message.chars();
                        chars.next();
                        chars.next_back();
                        chars.as_str().to_string()
                    },
                    Err(err_message) => err_message
                }
            },
            Msg::HashInputChange(hash) => {
                let re = Regex::new(r"^[0-9\s,]+$").unwrap();

                match re.is_match(&hash) {
                    true => {
                        self.hash_input = hash.clone();

                        match encryption::str_to_bytes(&self.hash_input) {
                            Ok(bytes_vec) => {
                                self.encoded_message = match encryption::decrypt(
                                    bytes_vec.as_slice(),
                                    self.secret_key.as_bytes()
                                ) {
                                    Ok(decrypted_message) => {
                                        match std::str::from_utf8(&decrypted_message) {
                                            Ok(message) => message.to_string(),
                                            Err(_) => String::from("Не удалось расшифровать сообщение")
                                        }
                                    },
                                    Err(err_message) => err_message
                                }
                            },
                            Err(err_message) => {
                                self.encoded_message = err_message
                            }
                        }
                    },
                    false => {
                        self.hash_input = String::new();
                        self.encoded_message = String::new();
                    }
                }
            }
        }
        true
    }

    fn view(&self, ctx: &Context<Self>) -> Html {
        let link = ctx.link();

        let on_secret_key_input_change = link.batch_callback(|e: InputEvent| {
            let input = e.target_dyn_into::<HtmlInputElement>();
            input.map(|input| Msg::SecretKeyChange(input.value()))
        });

        let on_message_input_change = link.batch_callback(|e: InputEvent| {
            let input = e.target_dyn_into::<HtmlInputElement>();
            input.map(|input| Msg::MessageInputChange(input.value()))
        });

        let on_hash_input_change = link.batch_callback(|e: InputEvent| {
            let input = e.target_dyn_into::<HtmlInputElement>();
            input.map(|input| Msg::HashInputChange(input.value()))
        });

        html! {
            <main>
            <form class="message-form">
                <label for="secret-key">{ "Ключ шифрования" }</label>
                <input
                    type="text"
                    class="secret-key-input"
                    id="secret-key"
                    name="secret-key"
                    minlength="1"
                    placeholder="SECRET_KEY_WITH_LENGTH_32_BYTES_"
                    oninput={on_secret_key_input_change}
                    // pattern=r"^[a-zA-Z0-9]+$"
                />
                <span class="invalid-secret-key-label">
                    { "Ключ должен содержать только буквы латинского алфавита или цифры" }
                </span>
                <h3 class="form-title">{ "Шифрование" }</h3>
                <label for="message">{ "Сообщение" }</label>
                <input
                    type="text"
                    class="message-input"
                    id="message"
                    name="message"
                    oninput={on_message_input_change}
                    // pattern=r"^[a-zA-Z0-9]+$"
                />
                <span class="invalid-message-label">
                    { "Можно ввести только символы латинского алфавита и цифры" }
                </span>
                <p class="form-output__label">{ "Зашифрованный массив байт:" }</p>
                <p class="form-output">{ &self.message_hash }</p>
            </form>
            <form class="hash-form">
                <h3 class="form-title">{ "Расшифровка" }</h3>
                <label for="hash">{ "Зашифрованный массив байт" }</label>
                <input
                    type="text"
                    class="hash-input"
                    id="hash"
                    name="hash"
                    oninput={on_hash_input_change}
                    pattern=r"^[0-9\s,]+$"
                />
                <span class="invalid-hash-label">
                    { "Можно ввести только числа, пробелы и запятые" }
                </span>
                <p class="form-output__label">{ "Сообщение:" }</p>
                <p class="form-output">{ &self.encoded_message }</p>
            </form>
            </main>
        }
    }
}

fn main() {
    wasm_logger::init(wasm_logger::Config::default());
    yew::start_app::<Model>();
}
