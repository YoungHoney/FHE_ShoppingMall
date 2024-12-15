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

class Coupon
{
public:
    std::string name;
    double rate;

    Coupon(const std::string &name, double rate) : name(name), rate(rate) {}
};

class Client
{
public:
    int id;
    std::string name;
    std::string address;
    std::vector<Coupon> coupons;

    Client(int id, const std::string &name, const std::string &address)
        : id(id), name(name), address(address) {}

    void addCoupon(const Coupon &c) { coupons.push_back(c); }

    void viewCoupons()
    {
        std::cout << "\nAvailable Coupons:\n";
        for (size_t i = 0; i < coupons.size(); i++)
        {
            std::cout << i + 1 << ". " << coupons[i].name
                      << " - Discount Rate: " << coupons[i].rate * 100 << "%\n";
        }
    }

    Coupon getCoupon(int index)
    {
        if (index < 1 || index > (int)coupons.size())
        {
            throw std::out_of_range("Invalid coupon selection.");
        }
        return coupons[index - 1];
    }
};

class Product
{
public:
    int id;
    std::string name;
    double price;

    Product(int id, const std::string &name, double price)
        : id(id), name(name), price(price) {}
};

class ShoppingMall
{
private:
    CryptoContext<DCRTPoly> cryptoContext;
    KeyPair<DCRTPoly> keyPair;

    std::vector<Product> products;
    std::vector<Client *> clients;
    Client *currentClient = nullptr;

public:
    void initializeCrypto()
    {
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

    bool loadState()
    {
        if (!std::filesystem::exists(DATAFOLDER))
        {
            std::cerr << "Error: Data folder does not exist.\n";
            return false;
        }

        try
        {
            if (!Serial::DeserializeFromFile(DATAFOLDER + "/cryptocontext.txt", cryptoContext, SerType::BINARY))
            {
                throw std::runtime_error("Failed to load CryptoContext.");
            }

            if (!Serial::DeserializeFromFile(DATAFOLDER + "/key-public.txt", keyPair.publicKey, SerType::BINARY))
            {
                throw std::runtime_error("Failed to load public key.");
            }

            if (!Serial::DeserializeFromFile(DATAFOLDER + "/key-private.txt", keyPair.secretKey, SerType::BINARY))
            {
                throw std::runtime_error("Failed to load secret key.");
            }

            std::ifstream emkeys(DATAFOLDER + "/key-eval-mult.txt", std::ios::in | std::ios::binary);
            if (!emkeys.is_open() || !cryptoContext->DeserializeEvalMultKey(emkeys, SerType::BINARY))
            {
                throw std::runtime_error("Failed to load EvalMultKey.");
            }

            emkeys.close();
            std::cout << "State successfully loaded.\n";
            return true;
        }
        catch (const std::exception &e)
        {
            std::cerr << "Error loading state: " << e.what() << "\n";
            return false;
        }
    }

    void saveState()
    {
        if (!std::filesystem::exists(DATAFOLDER))
        {
            std::filesystem::create_directory(DATAFOLDER);
        }

        std::string cryptoContextFile = DATAFOLDER + "/cryptocontext.txt";
        Serial::SerializeToFile(cryptoContextFile, cryptoContext, SerType::BINARY);

        std::string publicKeyFile = DATAFOLDER + "/key-public.txt";
        Serial::SerializeToFile(publicKeyFile, keyPair.publicKey, SerType::BINARY);

        std::string privateKeyFile = DATAFOLDER + "/key-private.txt";
        Serial::SerializeToFile(privateKeyFile, keyPair.secretKey, SerType::BINARY);

        std::string evalMultKeyFile = DATAFOLDER + "/key-eval-mult.txt";
        std::ofstream emkeys(evalMultKeyFile, std::ios::out | std::ios::binary);
        cryptoContext->SerializeEvalMultKey(emkeys, SerType::BINARY);
        emkeys.close();

        sendToServer_Context(cryptoContextFile, publicKeyFile, evalMultKeyFile);

        std::cout << "State successfully saved.\n";
    }

    void sendToServer_Context(const std::string &cryptoContextFile,
                              const std::string &publicKeyFile,
                              const std::string &evalMultKeyFile)
    {
        // 서버로 파일을 전송하는 부분은 구현하지 않음, 실제 응용시 전송부분 작성이 들어간다면 이곳에 들어가게 됨, SK는 클라이언트가 보유하므로 제외
        std::cout << "Sending files to server:\n";
        std::cout << "CryptoContext File: " << cryptoContextFile << "\n";
        std::cout << "Public Key File: " << publicKeyFile << "\n";
        std::cout << "EvalMultKey File: " << evalMultKeyFile << "\n";
    }

    void addProduct(int id, const std::string &name, double price)
    {
        products.push_back({id, name, price});
    }

    void addClient(Client &c) { clients.push_back(&c); }

    void selectClient(int clientId)
    {
        for (auto &client : clients)
        {
            if (client->id == clientId)
            {
                currentClient = client;
                std::cout << "Welcome, " << currentClient->name << "!\n";
                return;
            }
        }
        std::cout << "Client with ID " << clientId << " not found.\n";
        currentClient = nullptr;
    }

    void viewProducts()
    {
        std::cout << "\nAvailable Products:\n";
        for (const auto &product : products)
        {
            std::cout << "ID: " << product.id << ", Name: " << product.name
                      << ", Price: ₩" << product.price << "\n";
        }
    }
    void addToCart(int id, int quantity)
    {
        if (currentClient == nullptr)
        {
            std::cout << "No client selected.\n";
            return;
        }

        for (const auto &product : products)
        {
            if (product.id == id)
            {
                auto encryptedPrice = cryptoContext->Encrypt(
                    keyPair.publicKey,
                    cryptoContext->MakePackedPlaintext({static_cast<int64_t>(product.price)}));

                auto encryptedQuantity = cryptoContext->Encrypt(
                    keyPair.publicKey,
                    cryptoContext->MakePackedPlaintext({static_cast<int64_t>(quantity)}));

                // 파일 이름에 클라이언트 이름 추가
                std::string priceFile = DATAFOLDER + "/cart_price_" + currentClient->name + "_" + std::to_string(id) + ".txt";
                std::string quantityFile = DATAFOLDER + "/cart_quantity_" + currentClient->name + "_" + std::to_string(id) + ".txt";

                Serial::SerializeToFile(priceFile, encryptedPrice, SerType::BINARY);
                Serial::SerializeToFile(quantityFile, encryptedQuantity, SerType::BINARY);

                sendToServer_Cart(priceFile, quantityFile);

                std::cout << "Added \"" << product.name << "\" x" << quantity << " to cart for client ID: " << currentClient->id << ".\n";
                return;
            }
        }
        std::cout << "Product with ID " << id << " not found.\n";
    }

    void sendToServer_Cart(std::string price, std::string quantity)
    {

        // 서버로 파일을 전송하는 부분은 구현하지 않음, 실제 응용시 전송부분 작성이 들어간다면 이곳에 들어가게 됨
        std::cout << "Sending files to server:\n";
        std::cout << "price File: " << price << "\n";
        std::cout << "quantity File: " << quantity << "\n";
    }

    Ciphertext<DCRTPoly> serverside(double discountRate)
    {
        Ciphertext<DCRTPoly> encryptedTotal = cryptoContext->Encrypt(
            keyPair.publicKey, cryptoContext->MakePackedPlaintext({0}));

        const int64_t scaleFactor = 10;

        for (const auto &product : products)
        {
            std::string priceFile = DATAFOLDER + "/cart_price_" + currentClient->name + "_" + std::to_string(product.id) + ".txt";
            std::string quantityFile = DATAFOLDER + "/cart_quantity_" + currentClient->name + "_" + std::to_string(product.id) + ".txt";

            // 상품개수*상품가격 계산
            if (std::filesystem::exists(priceFile) && std::filesystem::exists(quantityFile))
            {
                Ciphertext<DCRTPoly> encryptedPrice;
                Ciphertext<DCRTPoly> encryptedQuantity;

                Serial::DeserializeFromFile(priceFile, encryptedPrice, SerType::BINARY);
                Serial::DeserializeFromFile(quantityFile, encryptedQuantity, SerType::BINARY);

                auto encryptedProduct = cryptoContext->EvalMult(encryptedPrice, encryptedQuantity);
                encryptedTotal = cryptoContext->EvalAdd(encryptedTotal, encryptedProduct);
            }
        }
        // 쿠폰에 의한 할인 계산

        auto encryptedDiscount = cryptoContext->Encrypt(
            keyPair.publicKey,
            cryptoContext->MakePackedPlaintext({static_cast<int64_t>((1 - discountRate) * scaleFactor)}));

        encryptedTotal = cryptoContext->EvalMult(encryptedTotal, encryptedDiscount);

        return encryptedTotal;
    }

    void clientside()
    {
        if (currentClient == nullptr)
        {
            std::cout << "No client selected.\n";
            return;
        }

        currentClient->viewCoupons();
        std::cout << "Select a coupon to apply: ";
        int choice;
        std::cin >> choice;

        try
        {
            // 클라이언트는 쿠폰을 고르고 쿠폰 연산은 서버에게 맡긴다.
            Coupon selectedCoupon = currentClient->getCoupon(choice);

            // 서버는 쿠폰할인율만 전송받고 기타 장바구니의 데이터는 별도로 암호화되고 직렬화되어 전송된 파일을읽어 따로 처리한다.
            Ciphertext<DCRTPoly> encryptedFinalTotal = serverside(selectedCoupon.rate);

            Plaintext decryptedTotal;
            cryptoContext->Decrypt(keyPair.secretKey, encryptedFinalTotal, &decryptedTotal);
            double finalTotal = static_cast<double>(decryptedTotal->GetPackedValue()[0]) / 10.0;

            std::cout << "Final Total after Discount: ₩" << finalTotal << "\n";
        }
        catch (const std::exception &e)
        {
            std::cout << "Error: " << e.what() << "\n";
        }
    }
};

int main()
{
    ShoppingMall mall;
    int choice;

    std::cout << "Select an option:\n";
    std::cout << "1. Initialize CryptoContext and Serialize State\n";
    std::cout << "2. Load State and Perform Shopping Mall Operations\n";
    std::cin >> choice;

    if (choice == 1)
    {
        mall.initializeCrypto();
    }
    else if (choice == 2)
    {
        if (mall.loadState())
        {
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
            do
            {
                std::cout << "\n--- Shopping Mall Menu ---\n";
                std::cout << "1. View Products\n";
                std::cout << "2. Add to Cart\n";
                std::cout << "3. Calculate Total\n";
                std::cout << "4. Exit\n";
                std::cout << "Enter your choice: ";
                std::cin >> menuChoice;

                switch (menuChoice)
                {
                case 1:
                    mall.viewProducts();
                    break;
                case 2:
                {
                    int productId, quantity;
                    std::cout << "Enter product ID to add to cart: ";
                    std::cin >> productId;
                    std::cout << "Enter quantity: ";
                    std::cin >> quantity;
                    mall.addToCart(productId, quantity);
                    break;
                }
                case 3:
                    mall.clientside();
                    break;
                case 4:
                    std::cout << "Thank you for visiting the shopping mall!\n";
                    break;
                default:
                    std::cout << "Invalid choice. Please try again.\n";
                }
            } while (menuChoice != 4);
        }
    }
    else
    {
        std::cout << "Invalid option.\n";
    }

    return 0;
}
