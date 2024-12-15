#include "openfhe.h"
#include "ciphertext-ser.h"
#include "cryptocontext-ser.h"
#include "key/key-ser.h"
#include <fstream>
#include <iostream>
#include <string>
#include <vector>
#include <filesystem>

using namespace lbcrypto;

const std::string DATAFOLDER = "shoppingMallData";

class Coupon {
public:
    std::string name;
    double rate; // 할인율 (0.1, 0.2 등)
};

class Client {
public:
    int id;
    std::string name;
    std::string address;
    std::vector<Coupon> coupons;

    Client(int id, const std::string &name, const std::string &address) {
        this->id = id;
        this->name = name;
        this->address = address;
    }

    void addCoupon(const Coupon &c) { coupons.push_back(c); }

    void viewCoupons() {
        std::cout << "\nAvailable Coupons:\n";
        for (size_t i = 0; i < coupons.size(); i++) {
            std::cout << i + 1 << ". " << coupons[i].name
                      << " - Discount Rate: " << coupons[i].rate * 100 << "%\n";
        }
    }

    Coupon getCoupon(int index) {
        if (index < 1 || index > (int)coupons.size()) {
            throw std::out_of_range("Invalid coupon selection.");
        }
        return coupons[index - 1];
    }
};

class Product {
public:
    int id;
    std::string name;
    double price; // 상품 가격
};

class ShoppingMall {
private:
    CryptoContext<DCRTPoly> cryptoContext;
    KeyPair<DCRTPoly> keyPair;

    std::vector<Product> products;
    std::vector<std::pair<Product, int>> cart;
    std::vector<Client *> clients;
    Client *currentClient = nullptr;

public:
    void initializeCrypto() {
        // Set CryptoContext parameters
        CCParams<CryptoContextBFVRNS> parameters;
        parameters.SetPlaintextModulus(1032193);
        parameters.SetMultiplicativeDepth(2);

        cryptoContext = GenCryptoContext(parameters);
        cryptoContext->Enable(PKE);
        cryptoContext->Enable(KEYSWITCH);
        cryptoContext->Enable(LEVELEDSHE);

        keyPair = cryptoContext->KeyGen();
        cryptoContext->EvalMultKeyGen(keyPair.secretKey);

        saveState();
        std::cout << "CryptoContext and keys have been initialized and saved.\n";
    }

    bool loadState() {
        if (!std::filesystem::exists(DATAFOLDER)) {
            std::cerr << "Error: Data folder does not exist.\n";
            return false;
        }

        try {
            if (!Serial::DeserializeFromFile(DATAFOLDER + "/cryptocontext.txt", cryptoContext, SerType::BINARY)) {
                throw std::runtime_error("Failed to load CryptoContext.");
            }

            if (!Serial::DeserializeFromFile(DATAFOLDER + "/key-public.txt", keyPair.publicKey, SerType::BINARY)) {
                throw std::runtime_error("Failed to load public key.");
            }

            if (!Serial::DeserializeFromFile(DATAFOLDER + "/key-private.txt", keyPair.secretKey, SerType::BINARY)) {
                throw std::runtime_error("Failed to load secret key.");
            }

            std::ifstream emkeys(DATAFOLDER + "/key-eval-mult.txt", std::ios::in | std::ios::binary);
            if (!emkeys.is_open() || !cryptoContext->DeserializeEvalMultKey(emkeys, SerType::BINARY)) {
                throw std::runtime_error("Failed to load EvalMultKey.");
            }

            emkeys.close();
            std::cout << "State successfully loaded.\n";
            return true;
        } catch (const std::exception &e) {
            std::cerr << "Error loading state: " << e.what() << "\n";
            return false;
        }
    }

    void saveState() {
        if (!std::filesystem::exists(DATAFOLDER)) {
            std::filesystem::create_directory(DATAFOLDER);
        }

        Serial::SerializeToFile(DATAFOLDER + "/cryptocontext.txt", cryptoContext, SerType::BINARY);
        Serial::SerializeToFile(DATAFOLDER + "/key-public.txt", keyPair.publicKey, SerType::BINARY);
        Serial::SerializeToFile(DATAFOLDER + "/key-private.txt", keyPair.secretKey, SerType::BINARY);

        std::ofstream emkeys(DATAFOLDER + "/key-eval-mult.txt", std::ios::out | std::ios::binary);
        cryptoContext->SerializeEvalMultKey(emkeys, SerType::BINARY);
        emkeys.close();

        std::cout << "State successfully saved.\n";
    }

    void addProduct(int id, const std::string &name, double price) {
        products.push_back({id, name, price});
    }

    void addClient(Client &c) { clients.push_back(&c); }

    void selectClient(int clientId) {
        for (auto &client : clients) {
            if (client->id == clientId) {
                currentClient = client;
                std::cout << "Welcome, " << currentClient->name << "!\n";
                return;
            }
        }
        std::cout << "Client with ID " << clientId << " not found.\n";
        currentClient = nullptr;
    }

    void viewProducts() {
        std::cout << "\nAvailable Products:\n";
        for (const auto &product : products) {
            std::cout << "ID: " << product.id << ", Name: " << product.name
                      << ", Price: ₩" << product.price << "\n";
        }
    }

    void addToCart(int id, int quantity) {
        for (const auto &product : products) {
            if (product.id == id) {
                cart.emplace_back(product, quantity);
                std::cout << "Added \"" << product.name << "\" x" << quantity
                          << " to cart.\n";
                return;
            }
        }
        std::cout << "Product with ID " << id << " not found.\n";
    }

    void calculateTotal() {
        if (currentClient == nullptr) {
            std::cout << "No client selected.\n";
            return;
        }

        Ciphertext<DCRTPoly> encryptedTotal = cryptoContext->Encrypt(
            keyPair.publicKey, cryptoContext->MakePackedPlaintext({0}));

        const int64_t scaleFactor = 10;
        for (const auto &entry : cart) {
            auto encryptedPrice = cryptoContext->Encrypt(
                keyPair.publicKey,
                cryptoContext->MakePackedPlaintext({static_cast<int64_t>(entry.first.price)}));
            auto encryptedQuantity = cryptoContext->Encrypt(
                keyPair.publicKey,
                cryptoContext->MakePackedPlaintext({static_cast<int64_t>(entry.second)}));
            auto encryptedProduct = cryptoContext->EvalMult(encryptedPrice, encryptedQuantity);
            encryptedTotal = cryptoContext->EvalAdd(encryptedTotal, encryptedProduct);
        }

        currentClient->viewCoupons();
        std::cout << "Select a coupon to apply: ";
        int choice;
        std::cin >> choice;
        Coupon selectedCoupon = currentClient->getCoupon(choice);

        auto encryptedDiscount = cryptoContext->Encrypt(
            keyPair.publicKey,
            cryptoContext->MakePackedPlaintext({static_cast<int64_t>((1 - selectedCoupon.rate) * scaleFactor)}));

        encryptedTotal = cryptoContext->EvalMult(encryptedTotal, encryptedDiscount);

        Plaintext decryptedTotal;
        cryptoContext->Decrypt(keyPair.secretKey, encryptedTotal, &decryptedTotal);
        double finalTotal = static_cast<double>(decryptedTotal->GetPackedValue()[0]) / scaleFactor;

        std::cout << "Final Total after Discount: ₩" << finalTotal << "\n";
    }
};

int main() {
    ShoppingMall mall;
    int choice;

    std::cout << "Select an option:\n";
    std::cout << "1. Initialize CryptoContext and Serialize State\n";
    std::cout << "2. Load State and Perform Shopping Mall Operations\n";
    std::cin >> choice;

    if (choice == 1) {
        mall.initializeCrypto();
    } else if (choice == 2) {
        if (mall.loadState()) {
            Client C1 = {1, "Tom", "84, Heukseok-ro, Dongjak-gu, Seoul"};
            Client C2 = {2, "James", "90 Hyeonchung-ro, Dongjak-gu, Seoul"};
            mall.addClient(C1);
            mall.addClient(C2);

            Coupon cp1 = {"Welcome Coupon", 0.1};
            Coupon cp2 = {"Great Coupon", 0.5};
            C1.addCoupon(cp1);
            C2.addCoupon(cp1);
            C2.addCoupon(cp2);

            mall.addProduct(1, "Onion", 1000);
            mall.addProduct(2, "Eggs", 200);
            mall.addProduct(3, "Tomato", 1500);

            int clientId;
            std::cout << "Enter your client ID to log in: ";
            std::cin >> clientId;
            mall.selectClient(clientId);

            int menuChoice;
            do {
                std::cout << "\n--- Shopping Mall Menu ---\n";
                std::cout << "1. View Products\n";
                std::cout << "2. Add to Cart\n";
                std::cout << "3. Calculate Total\n";
                std::cout << "4. Exit\n";
                std::cout << "Enter your choice: ";
                std::cin >> menuChoice;

                switch (menuChoice) {
                case 1:
                    mall.viewProducts();
                    break;
                case 2: {
                    int productId, quantity;
                    std::cout << "Enter product ID to add to cart: ";
                    std::cin >> productId;
                    std::cout << "Enter quantity: ";
                    std::cin >> quantity;
                    mall.addToCart(productId, quantity);
                    break;
                }
                case 3:
                    mall.calculateTotal();
                    break;
                case 4:
                    std::cout << "Thank you for visiting the shopping mall!\n";
                    break;
                default:
                    std::cout << "Invalid choice. Please try again.\n";
                }
            } while (menuChoice != 4);
        }
    } else {
        std::cout << "Invalid option.\n";
    }

    return 0;
}
