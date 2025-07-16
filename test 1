import asyncio
import os
import random
import logging
from aioquic.asyncio import serve, connect
from aioquic.quic.configuration import QuicConfiguration
from aioquic.h3.connection import H3Connection
from aioquic.h3.events import HeadersReceived, DataReceived
from aioquic.quic.events import StreamDataReceived
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import oqs
import json

# Настройка логирования
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

# Шаблоны для динамической обфускации
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.5 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0"
]
PATHS = [
    "/index.html", "/api/v1/data", "/static/style.css", "/page/home", "/assets/image.jpg", "/api/auth/login"
]
ACCEPTS = [
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
    "application/json, text/plain, */*",
    "*/*"
]
ACCEPT_LANGUAGES = [
    "en-US,en;q=0.9", "ru-RU,ru;q=0.8,en-US;q=0.7", "en-GB,en;q=0.9"
]

# Функция для генерации динамических HTTP/3 заголовков
def generate_dynamic_headers():
    return [
        (":method", random.choice(["GET", "POST"])),
        (":scheme", "https"),
        (":path", random.choice(PATHS)),
        (":authority", random.choice(["example.com", "api.example.com", "cdn.example.com"])),
        ("user-agent", random.choice(USER_AGENTS)),
        ("accept", random.choice(ACCEPTS)),
        ("accept-language", random.choice(ACCEPT_LANGUAGES))
    ]

# Функция для генерации случайного padding (имитация веб-данных)
def generate_random_padding():
    padding_types = [
        json.dumps({"status": "ok", "data": random.randint(1, 1000)}).encode(),
        b"<div>" + os.urandom(random.randint(10, 50)) + b"</div>",
        os.urandom(random.randint(10, 50))
    ]
    return random.choice(padding_types)

class ChameleonProtocol(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._http = H3Connection(self._quic)  # HTTP/3 с QPACK
        self.streams = {}
        self.rotate_keys()  # Инициализация ключей

    def rotate_keys(self):
        """Генерация новой пары ключей Kyber1024 для нового соединения"""
        try:
            self.kem = oqs.KeyEncapsulation("Kyber1024")
            self.public_key = self.kem.generate_keypair()
            self.shared_secret = None
            self.aes_key = None
            logger.info("Ключи Kyber1024 сгенерированы для нового соединения")
        except Exception as e:
            logger.error(f"Ошибка при ротации ключей: {e}")
            raise

    def derive_key(self, shared_secret):
        """Вывод ключа для AES-GCM из shared_secret с помощью HKDF"""
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"chameleon_vpn",
        )
        return hkdf.derive(shared_secret)

    def quic_event_received(self, event):
        """Обработка QUIC и HTTP/3 событий"""
        if isinstance(event, StreamDataReceived):
            if event.stream_id not in self.streams:
                self.streams[event.stream_id] = {"buffer": b""}
                self.rotate_keys()  # Ротация ключей для нового потока
                asyncio.create_task(self.handle_stream(event.stream_id))
            self.streams[event.stream_id]["buffer"] += event.data
            if event.end_stream:
                self._http.handle_event(event)
        elif isinstance(event, HeadersReceived):
            self.handle_headers(event.stream_id, event.headers)
        elif isinstance(event, DataReceived):
            self.handle_data(event.stream_id, event.data)

    def handle_headers(self, stream_id, headers):
        """Обработка HTTP/3 заголовков"""
        logger.info(f"Получены заголовки на потоке {stream_id}: {headers}")
        # Отправляем динамические заголовки для обфускации
        self._http.send_headers(stream_id, generate_dynamic_headers(), end_stream=False)

    def handle_data(self, stream_id, data):
        """Обработка данных с обфускацией и шифрованием"""
        try:
            decrypted_data = self.decrypt_data(data)
            logger.info(f"Сервер получил: {decrypted_data.decode()}")
            response = self.encrypt_data(b"Ответ от сервера!")
            self._http.send_data(stream_id, self.obfuscate_data(response), end_stream=True)
            # Отправляем случайный HTTP/3 фрейм для обфускации
            self._http.send_headers(stream_id, [(":method", "SETTINGS")], end_stream=False)
        except Exception as e:
            logger.error(f"Ошибка обработки данных: {e}")

    async def handle_stream(self, stream_id):
        """Инициализация потока с Kyber"""
        try:
            client_public_key = self.streams.get(stream_id, {}).get("buffer", b"")
            if not client_public_key:
                logger.error("No client public key received")
                return

            ciphertext, self.shared_secret = self.kem.encap_secret(client_public_key)
            self.aes_key = self.derive_key(self.shared_secret)
            self._http.send_data(stream_id, ciphertext, end_stream=False)
            logger.info(f"Поток {stream_id}: Общий секрет установлен")
        except Exception as e:
            logger.error(f"Ошибка в инициализации потока {stream_id}: {e}")

    def obfuscate_data(self, data):
        """Динамическая обфускация с HTTP/3 заголовками и padding"""
        headers = generate_dynamic_headers()
        self._http.send_headers(stream_id=None, headers=headers, end_stream=False)
        padding = generate_random_padding()
        return base64.b64encode(data) + padding

    def encrypt_data(self, data):
        """Шифрование данных с помощью AES-GCM"""
        if not self.aes_key:
            raise ValueError("AES key not initialized")
        aesgcm = AESGCM(self.aes_key)
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, data, None)
        return nonce + ciphertext

    def decrypt_data(self, data):
        """Дешифрование данных"""
        if not self.aes_key:
            raise ValueError("AES key not initialized")
        # Удаляем padding (предполагаем, что это base64)
        data = data[:data.rindex(b'=') + 1] if b'=' in data else data
        data = base64.b64decode(data)
        nonce, ciphertext = data[:12], data[12:]
        aesgcm = AESGCM(self.aes_key)
        return aesgcm.decrypt(nonce, ciphertext, None)

async def run_server():
    try:
        # Генерация самоподписанного сертификата
        if not os.path.exists("cert.pem") or not os.path.exists("key.pem"):
            logger.info("Генерация самоподписанного сертификата...")
            os.system("openssl req -x509 -newkey rsa:2048 -nodes -days 365 -keyout key.pem -out cert.pem -subj '/CN=localhost'")

        # Настройка TLS 1.3 для QUIC
        configuration = QuicConfiguration(
            is_client=False,
            alpn_protocols=["h3"],
            supported_versions=[0x00000001],  # QUIC v1
            ciphers=[
                "TLS_AES_128_GCM_SHA256",
                "TLS_AES_256_GCM_SHA384",
                "TLS_CHACHA20_POLY1305_SHA256"
            ]
        )
        configuration.load_cert_chain(certfile="cert.pem", keyfile="key.pem")
        logger.info("Запуск сервера на 0.0.0.0:443")
        await serve(
            "0.0.0.0",
            443,
            configuration=configuration,
            create_protocol=ChameleonProtocol,
        )
        await asyncio.Event().wait()
    except Exception as e:
        logger.error(f"Ошибка сервера: {e}")

async def run_client(server_host, message):
    try:
        # Настройка TLS 1.3 для клиента
        configuration = QuicConfiguration(
            is_client=True,
            alpn_protocols=["h3"],
            supported_versions=[0x00000001],
            ciphers=[
                "TLS_AES_128_GCM_SHA256",
                "TLS_AES_256_GCM_SHA384",
                "TLS_CHACHA20_POLY1305_SHA256"
            ],
            verify=False  # Для тестов, в продакшене использовать cert.pem
        )
        async with connect(server_host, 443, configuration=configuration) as client:
            kem = oqs.KeyEncapsulation("Kyber1024")
            public_key = kem.generate_keypair()  # Ротация ключей
            http = H3Connection(client)
            stream_id = client.get_next_available_stream_id()

            # Отправка публичного ключа
            http.send_data(stream_id, public_key, end_stream=False)
            headers = generate_dynamic_headers()
            http.send_headers(stream_id, headers, end_stream=False)
            logger.info("Клиент: Отправлен новый публичный ключ Kyber1024")

            # Получение ответа
            async def read_stream():
                while True:
                    event = client.next_event()
                    if isinstance(event, StreamDataReceived):
                        ciphertext = event.data
                        shared_secret = kem.decap_secret(ciphertext)
                        aes_key = HKDF(
                            algorithm=hashes.SHA256(),
                            length=32,
                            salt=None,
                            info=b"chameleon_vpn",
                        ).derive(shared_secret)
                        logger.info("Клиент: Общий секрет установлен")
                        break

            await read_stream()

            # Отправка зашифрованного сообщения
            aesgcm = AESGCM(aes_key)
            nonce = os.urandom(12)
            encrypted_data = nonce + aesgcm.encrypt(nonce, message.encode(), None)
            http.send_data(stream_id, generate_dynamic_headers() + base64.b64encode(encrypted_data), end_stream=True)
            http.send_headers(stream_id, [(":method", "SETTINGS")], end_stream=False)  # Дополнительный фрейм

            # Получение ответа
            async def read_response():
                while True:
                    event = client.next_event()
                    if isinstance(event, DataReceived):
                        response = event.data
                        nonce, ciphertext = response[:12], response[12:]
                        decrypted_response = aesgcm.decrypt(nonce, ciphertext, None)
                        logger.info(f"Клиент получил: {decrypted_response.decode()}")
                        break

            await read_response()
    except Exception as e:
        logger.error(f"Ошибка клиента: {e}")

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Использование: python chameleon_prototype.py [server|client <host> <message>]")
    elif sys.argv[1] == "server":
        asyncio.run(run_server())
    elif sys.argv[1] == "client":
        asyncio.run(run_client(sys.argv[2], sys.argv[3]))
