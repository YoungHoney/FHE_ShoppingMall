#include "openfhe.h"
#include <fstream>
#include <iomanip>
#include <iostream>
#include <string>
#include <vector>
#include <filesystem> // for directory operations

using namespace lbcrypto;

class Coupon
{
public:
  std::string name;
  double rate; // 할인율 (0.1, 0.2 등)
};

class Client
{
public:
  int id;
  std::string name;
  std::string address;
  std::vector<Coupon> coupons;

  Client(int id, const std::string &name, const std::string &address)
  {
    this->id = id;
    this->name = name;
    this->address = address;
  }

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
  double price; // 상품 가격
};

class ShoppingMall
{
private:
  std::vector<Product> products;
  std::vector<std::pair<Product, int>> cart; // 상품과 개수
  std::vector<Client *> clients;
  Client *currentClient = nullptr;

  CryptoContext<DCRTPoly> cryptoContext;
  KeyPair<DCRTPoly> keyPair;

  const std::string DATAFOLDER = "shoppingmallData";

public:
  ShoppingMall()
  {
    // if (!loadState())
    // {
    // OpenFHE 초기화
    CCParams<CryptoContextBFVRNS> parameters;
    parameters.SetPlaintextModulus(1032193);
    parameters.SetMultiplicativeDepth(2);
    cryptoContext = GenCryptoContext(parameters);

    // 기능 활성화
    cryptoContext->Enable(PKE);
    cryptoContext->Enable(KEYSWITCH);
    cryptoContext->Enable(LEVELEDSHE);

    // 키 생성
    keyPair = cryptoContext->KeyGen();
    cryptoContext->EvalMultKeyGen(keyPair.secretKey);

    saveState(); // 초기화 상태 저장
    //  }
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
    for (const auto &product : products)
    {
      if (product.id == id)
      {
        cart.emplace_back(product, quantity);
        std::cout << "Added \"" << product.name << "\" x" << quantity
                  << " to cart.\n";
        return;
      }
    }
    std::cout << "Product with ID " << id << " not found.\n";
  }

  void calculateTotal()
  {
    if (currentClient == nullptr)
    {
      std::cout << "No client selected.\n";
      return;
    }
    // 총액 암호화
    Ciphertext<DCRTPoly> encryptedTotal = cryptoContext->Encrypt(
        keyPair.publicKey, cryptoContext->MakePackedPlaintext({0}));

    // 스케일링 팩터 설정
    const int64_t scaleFactor = 10;

    // 암호화된 품목 정보를 저장할 컨테이너
    std::vector<std::pair<Ciphertext<DCRTPoly>, Ciphertext<DCRTPoly>>> encryptedCart;
    for (const auto &entry : cart)
    {
      auto encryptedPrice = cryptoContext->Encrypt(
          keyPair.publicKey,
          cryptoContext->MakePackedPlaintext({static_cast<int64_t>(entry.first.price)}));
      auto encryptedQuantity = cryptoContext->Encrypt(
          keyPair.publicKey,
          cryptoContext->MakePackedPlaintext({static_cast<int64_t>(entry.second)}));

      auto encryptedProduct = cryptoContext->EvalMult(encryptedPrice, encryptedQuantity);
      encryptedTotal = cryptoContext->EvalAdd(encryptedTotal, encryptedProduct);

      // 암호화된 품목 정보 추가
      encryptedCart.push_back({encryptedPrice, encryptedQuantity});
    }

    // 쿠폰 적용
    currentClient->viewCoupons();
    std::cout << "Select a coupon to apply: ";
    int choice;
    std::cin >> choice;
    Coupon selectedCoupon = currentClient->getCoupon(choice);
    try
    {
      // 할인율 암호화
      auto encryptedDiscount = cryptoContext->Encrypt(
          keyPair.publicKey,
          cryptoContext->MakePackedPlaintext({static_cast<int64_t>((1 - selectedCoupon.rate) * scaleFactor)}));

      encryptedTotal = cryptoContext->EvalMult(encryptedTotal, encryptedDiscount);

      // 복호화 과정은 클라이언트에서 일어나는 과정.
      //  복호화
      Plaintext decryptedTotal;
      cryptoContext->Decrypt(keyPair.secretKey, encryptedTotal, &decryptedTotal);

      // 최종 결과 계산
      double finalTotal = static_cast<double>(decryptedTotal->GetPackedValue()[0]) / scaleFactor;
      std::cout << "Final Total after Discount: ₩" << finalTotal << "\n";

      // 영수증 저장
      saveOrderToFile(finalTotal, selectedCoupon);
      saveEncryptedReceiptToFile(encryptedTotal, encryptedCart, encryptedDiscount, selectedCoupon);
    }
    catch (std::out_of_range &e)
    {
      std::cout << e.what() << "\n";
    }
  }

  void saveOrderToFile(double total, Coupon c)
  {
    // 파일명 지정
    std::string fileName = "Order_" + currentClient->name + ".txt";

    // 텍스트 파일 열기
    std::ofstream outFile(fileName);
    if (!outFile)
    {
      std::cerr << "Failed to open file for writing: " << fileName << "\n";
      return;
    }

    // 파일에 내용 쓰기
    outFile << "Client Name: " << currentClient->name << "\n";
    outFile << "Address: " << currentClient->address << "\n\n";
    outFile << "Used Coupon: " << c.name << " rate : " << 100 * c.rate << "%\n\n";
    outFile << "Order Details:\n";

    for (const auto &entry : cart)
    {
      outFile << "- Product: " << entry.first.name
              << ", Quantity: " << entry.second
              << ", Unit Price: ₩" << entry.first.price << "\n";
    }

    outFile << "\nTotal Price (after discount): ₩" << total << "\n";

    outFile.close();

    std::cout << "Order has been saved to " << fileName << "\n";
  }

  void saveEncryptedReceiptToFile(
      Ciphertext<DCRTPoly> encryptedTotal,
      const std::vector<std::pair<Ciphertext<DCRTPoly>, Ciphertext<DCRTPoly>>> &encryptedCart,
      Ciphertext<DCRTPoly> encryptedDiscount,
      Coupon c)
  {
    // 파일명 지정
    std::string fileName = "Encrypted_Order_" + currentClient->name + ".bin";

    try
    {
      // 클라이언트 정보 저장 (텍스트 형식)
      std::ofstream metaFile("Meta_" + fileName, std::ios::out);
      if (!metaFile)
      {
        throw std::runtime_error("Failed to open meta file for writing.");
      }
      metaFile << "Client Name: " << currentClient->name << "\n";
      metaFile << "Address: " << currentClient->address << "\n\n";
      metaFile << "Used Coupon: " << c.name << " rate : " << 100 * c.rate << "%\n\n";
      metaFile << "Encrypted Order Details:\n";
      metaFile.close();

      // 암호화된 주문 데이터 저장
      for (size_t i = 0; i < encryptedCart.size(); i++)
      {
        if (!Serial::SerializeToFile(fileName + "_Price_" + std::to_string(i + 1) + ".bin", encryptedCart[i].first, SerType::BINARY))
          throw std::runtime_error("Failed to serialize encrypted price.");

        if (!Serial::SerializeToFile(fileName + "_Quantity_" + std::to_string(i + 1) + ".bin", encryptedCart[i].second, SerType::BINARY))
          throw std::runtime_error("Failed to serialize encrypted quantity.");
      }

      if (!Serial::SerializeToFile(fileName + "_Discount.bin", encryptedDiscount, SerType::BINARY))
        throw std::runtime_error("Failed to serialize encrypted discount.");

      if (!Serial::SerializeToFile(fileName + "_Total.bin", encryptedTotal, SerType::BINARY))
        throw std::runtime_error("Failed to serialize encrypted total.");

      std::cout << "Encrypted receipt has been saved with metadata and binary files.\n";
    }
    catch (const std::exception &e)
    {
      std::cerr << "Error saving encrypted receipt: " << e.what() << "\n";
    }
  }

  bool loadState()
  {
    lbcrypto::CryptoContextFactory<lbcrypto::DCRTPoly>::ReleaseAllContexts();
    if (!std::filesystem::exists(DATAFOLDER))
    {
      return false;
    }

    try // 서버 -> 클라이언트 전송 후 클라이언트 복원
    {
      // CryptoContext 복원
      if (!Serial::DeserializeFromFile(DATAFOLDER + "/cryptocontext.txt", cryptoContext, SerType::BINARY))
      {
        std::cerr << "Failed to load crypto context.\n";
        return false;
      }

      // 공개 키 복원
      if (!Serial::DeserializeFromFile(DATAFOLDER + "/key-public.txt", keyPair.publicKey, SerType::BINARY))
      {
        std::cerr << "Failed to load public key.\n";
        return false;
      }

      // 비밀 키 복원
      if (!Serial::DeserializeFromFile(DATAFOLDER + "/key-private.txt", keyPair.secretKey, SerType::BINARY))
      {
        std::cerr << "Failed to load private key.\n";
        return false;
      }

      // EvalMultKey 복원
      std::ifstream emkeys(DATAFOLDER + "/key-eval-mult.txt", std::ios::in | std::ios::binary);
      if (emkeys.is_open())
      {
        if (!cryptoContext->DeserializeEvalMultKey(emkeys, SerType::BINARY))
        {
          std::cerr << "Failed to load EvalMultKey.\n";
          return false;
        }
        emkeys.close();
      }
      else
      {
        std::cerr << "Failed to open EvalMultKey file.\n";
        return false;
      }

      std::cout << "State successfully loaded from " << DATAFOLDER << ".\n";
      std::cout << "CryptoContext tag: " << cryptoContext->GetCryptoParameters()->GetParamsPK() << "\n";

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
    // 디렉토리 생성
    if (!std::filesystem::exists(DATAFOLDER))
    {
      std::filesystem::create_directory(DATAFOLDER);
    }

    try // 클라이언트 -> 서버
    {
      // CryptoContext 직렬화
      if (!Serial::SerializeToFile(DATAFOLDER + "/cryptocontext.txt", cryptoContext, SerType::BINARY))
      {
        throw std::runtime_error("Failed to save crypto context.");
      }

      // 공개 키 직렬화
      if (!Serial::SerializeToFile(DATAFOLDER + "/key-public.txt", keyPair.publicKey, SerType::BINARY))
      {
        throw std::runtime_error("Failed to save public key.");
      }

      //...

      // EvalMultKey 직렬화
      std::ofstream emkeys(DATAFOLDER + "/key-eval-mult.txt", std::ios::out | std::ios::binary);
      if (emkeys.is_open())
      {
        if (!cryptoContext->SerializeEvalMultKey(emkeys, SerType::BINARY))
        {
          throw std::runtime_error("Failed to save EvalMultKey.");
        }
        emkeys.close();
      }
      else
      {
        throw std::runtime_error("Failed to open EvalMultKey file for writing.");
      }

      std::cout << "State successfully saved to " << DATAFOLDER << ".\n";
      std::cout << "CryptoContext tag: " << cryptoContext->GetCryptoParameters()->GetParamsPK() << "\n";
    }
    catch (const std::exception &e)
    {
      std::cerr << "Error saving state: " << e.what() << "\n";
    }
  }
};

int main()
{
  ShoppingMall mall;

  // 고객 및 상품 설정
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

  // 메뉴 실행
  int choice = 0;
  do
  {
    std::cout << "\n--- Shopping Mall Menu ---\n";
    std::cout << "1. View Products\n";
    std::cout << "2. Add to Cart\n";
    std::cout << "3. Calculate Total\n";
    std::cout << "4. Exit\n";
    std::cout << "Enter your choice: ";
    std::cin >> choice;

    switch (choice)
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

      mall.calculateTotal();
      break;
    case 4:
      std::cout << "Thank you for visiting the shopping mall!\n";
      break;
    default:
      std::cout << "Invalid choice. Please try again.\n";
    }
  } while (choice != 4);

  return 0;
}
