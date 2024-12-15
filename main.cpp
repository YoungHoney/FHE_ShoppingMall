#include "openfhe.h"
#include "ciphertext-ser.h"
#include "cryptocontext-ser.h"
#include "key/key-ser.h"
#include <fstream>
#include <iostream>
#include <vector>
#include <filesystem>

using namespace lbcrypto;

const std::string CLIENTFOLDER = "clientData";
const std::string SERVERFOLDER = "serverData";

class Client {
public:
    int id;
    std::string name;
    std::string address;
    Client(int id, const std::string &name, const std::string &address)
        : id(id), name(name), address(address) {}
};

class Product {
public:
    int id;
    std::string name;
    double price;
    Product(int id, const std::string &name, double price)
        : id(id), name(name), price(price) {}
};

class ShoppingMallClient {
private:
    CryptoContext<DCRTPoly> cryptoContext;
    KeyPair<DCRTPoly> keyPair;

public:
    void initializeClient() {
        CCParams<CryptoContextBFVRNS> parameters;
        parameters.SetPlaintextModulus(1032193);
        parameters.SetMultiplicativeDepth(2);

        cryptoContext = GenCryptoContext(parameters);
        cryptoContext->Enable(PKE);
        cryptoContext->Enable(KEYSWITCH);
        cryptoContext->Enable(LEVELEDSHE);

        keyPair = cryptoContext->KeyGen();
        cryptoContext->EvalMultKeyGen(keyPair.secretKey);

        saveClientState();
        std::cout << "Client initialized. Keys and context saved.\n";
    }

    void saveClientState() {
        if (!std::filesystem::exists(CLIENTFOLDER)) {
            std::filesystem::create_directory(CLIENTFOLDER);
        }

        Serial::SerializeToFile(CLIENTFOLDER + "/cryptocontext.txt", cryptoContext, SerType::BINARY);
        Serial::SerializeToFile(CLIENTFOLDER + "/key-public.txt", keyPair.publicKey, SerType::BINARY);
        Serial::SerializeToFile(CLIENTFOLDER + "/key-private.txt", keyPair.secretKey, SerType::BINARY);

        std::cout << "Client state saved.\n";
    }

    bool loadClientState() {
        try {
            if (!Serial::DeserializeFromFile(CLIENTFOLDER + "/cryptocontext.txt", cryptoContext, SerType::BINARY)) {
                throw std::runtime_error("Failed to load CryptoContext.");
            }
            if (!Serial::DeserializeFromFile(CLIENTFOLDER + "/key-public.txt", keyPair.publicKey, SerType::BINARY)) {
                throw std::runtime_error("Failed to load Public Key.");
            }
            if (!Serial::DeserializeFromFile(CLIENTFOLDER + "/key-private.txt", keyPair.secretKey, SerType::BINARY)) {
                throw std::runtime_error("Failed to load Secret Key.");
            }
            std::cout << "Client state loaded.\n";
            return true;
        } catch (const std::exception &e) {
            std::cerr << "Error loading client state: " << e.what() << "\n";
            return false;
        }
    }

    void encryptCartItem(int price, int quantity) {
        if (!std::filesystem::exists(SERVERFOLDER)) {
            std::filesystem::create_directory(SERVERFOLDER);
        }

        auto plaintextPrice = cryptoContext->MakePackedPlaintext({price});
        auto plaintextQuantity = cryptoContext->MakePackedPlaintext({quantity});

        auto encryptedPrice = cryptoContext->Encrypt(keyPair.publicKey, plaintextPrice);
        auto encryptedQuantity = cryptoContext->Encrypt(keyPair.publicKey, plaintextQuantity);

        Serial::SerializeToFile(SERVERFOLDER + "/encryptedPrice.txt", encryptedPrice, SerType::BINARY);
        Serial::SerializeToFile(SERVERFOLDER + "/encryptedQuantity.txt", encryptedQuantity, SerType::BINARY);

        std::cout << "Encrypted cart item saved to server folder.\n";
    }

    void decryptTotal() {
        Ciphertext<DCRTPoly> encryptedTotal;
        if (!Serial::DeserializeFromFile(CLIENTFOLDER + "/encryptedTotal.txt", encryptedTotal, SerType::BINARY)) {
            std::cerr << "Failed to load encrypted total.\n";
            return;
        }

        Plaintext plaintextTotal;
        cryptoContext->Decrypt(keyPair.secretKey, encryptedTotal, &plaintextTotal);

        std::cout << "Decrypted total: " << plaintextTotal->GetPackedValue()[0] << "\n";
    }
};

class ShoppingMallServer {
private:
    CryptoContext<DCRTPoly> cryptoContext;

public:
    bool loadServerState() {
        try {
            if (!Serial::DeserializeFromFile(CLIENTFOLDER + "/cryptocontext.txt", cryptoContext, SerType::BINARY)) {
                throw std::runtime_error("Failed to load CryptoContext.");
            }
            std::cout << "Server state loaded.\n";
            return true;
        } catch (const std::exception &e) {
            std::cerr << "Error loading server state: " << e.what() << "\n";
            return false;
        }
    }

    void calculateTotal() {
        Ciphertext<DCRTPoly> encryptedPrice, encryptedQuantity;

        if (!Serial::DeserializeFromFile(SERVERFOLDER + "/encryptedPrice.txt", encryptedPrice, SerType::BINARY)) {
            std::cerr << "Failed to load encrypted price.\n";
            return;
        }
        if (!Serial::DeserializeFromFile(SERVERFOLDER + "/encryptedQuantity.txt", encryptedQuantity, SerType::BINARY)) {
            std::cerr << "Failed to load encrypted quantity.\n";
            return;
        }

        auto encryptedTotal = cryptoContext->EvalMult(encryptedPrice, encryptedQuantity);

        if (!std::filesystem::exists(CLIENTFOLDER)) {
            std::filesystem::create_directory(CLIENTFOLDER);
        }
        Serial::SerializeToFile(CLIENTFOLDER + "/encryptedTotal.txt", encryptedTotal, SerType::BINARY);

        std::cout << "Encrypted total saved for client.\n";
    }
};

int main() {
    ShoppingMallClient client;
    ShoppingMallServer server;

    // 기본 상품 목록과 클라이언트 정보
    std::vector<Product> products = {
        {1, "Tomato", 1500},
        {2, "Eggs", 200},
        {3, "Onion", 1000}
    };
    std::vector<Client> clients = {
        {1, "Alice", "123 Wonderland St"},
        {2, "Bob", "456 Nowhere Ave"}
    };

    int choice;
    std::cout << "Select an option:\n";
    std::cout << "1. Initialize Client\n";
    std::cout << "2. Add Cart Item (Client)\n";
    std::cout << "3. Calculate Total (Server)\n";
    std::cout << "4. Decrypt Total (Client)\n";
    std::cout << "5. View Products\n";
    std::cin >> choice;

    switch (choice) {
    case 1:
        client.initializeClient();
        break;
    case 2: {
        if (client.loadClientState()) {
            int productId, quantity;
            std::cout << "Available Products:\n";
            for (const auto &product : products) {
                std::cout << product.id << ": " << product.name << " - ₩" << product.price << "\n";
            }
            std::cout << "Enter product ID to add: ";
            std::cin >> productId;
            std::cout << "Enter quantity: ";
            std::cin >> quantity;

            auto it = std::find_if(products.begin(), products.end(), [productId](const Product &p) {
                return p.id == productId;
            });

            if (it != products.end()) {
                client.encryptCartItem(static_cast<int>(it->price), quantity);
            } else {
                std::cout << "Invalid product ID.\n";
            }
        }
        break;
    }
    case 3:
        if (server.loadServerState()) {
            server.calculateTotal();
        }
        break;
    case 4:
        if (client.loadClientState()) {
            client.decryptTotal();
        }
        break;
    case 5:
        for (const auto &product : products) {
            std::cout << product.id << ": " << product.name << " - ₩" << product.price << "\n";
        }
        break;
    default:
        std::cout << "Invalid option.\n";
    }

    return 0;
}
