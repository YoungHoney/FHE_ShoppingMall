#include <fstream>
#include <iomanip>
#include <iostream>
#include <string>
#include <vector>

class Coupon {
public:
  std::string name;
  double rate;
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
  double price;

  void applyDiscount(double discountRate) { price *= (1 - discountRate); }
};

class ShoppingMall {
private:
  std::vector<Product> products;
  std::vector<Product> cart;
  std::vector<Client *> clients;
  Client *currentClient = nullptr;

public:
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

  void addToCart(int id) {
    for (const auto &product : products) {
      if (product.id == id) {
        cart.push_back(product);
        std::cout << "Added \"" << product.name << "\" to cart.\n";
        return;
      }
    }
    std::cout << "Product with ID " << id << " not found.\n";
  }

  void viewCart() {
    std::cout << "\nYour Cart:\n";
    double total = 0.0;
    for (const auto &product : cart) {
      std::cout << "Name: " << product.name << ", Price: ₩" << product.price
                << "\n";
      total += product.price;
    }
    std::cout << "Total: ₩" << total << "\n";
  }

  void applyCoupon() {
    if (currentClient == nullptr) {
      std::cout << "No client selected.\n";
      return;
    }
    currentClient->viewCoupons();
    std::cout << "Select a coupon to apply: ";
    int choice;
    std::cin >> choice;

    try {
      Coupon selectedCoupon = currentClient->getCoupon(choice);
      for (auto &product : cart) {
        product.applyDiscount(selectedCoupon.rate);
      }
      std::cout << "Coupon \"" << selectedCoupon.name
                << "\" applied successfully!\n";
    } catch (std::out_of_range &e) {
      std::cout << e.what() << "\n";
    }
  }

  void confirmOrder() {
    if (currentClient == nullptr) {
      std::cout << "No client selected.\n";
      return;
    }

    std::string filename = currentClient->name + "_receipt.txt";
    std::ofstream receipt(filename);

    if (!receipt) {
      std::cerr << "Failed to create receipt file.\n";
      return;
    }

    double total = 0.0;
    receipt << "Receipt for " << currentClient->name << "\n";
    receipt << "Address: " << currentClient->address << "\n\n";
    receipt << "Products Purchased:\n";

    for (const auto &product : cart) {
      receipt << "Name: " << product.name << ", Price: ₩" << std::fixed
              << std::setprecision(2) << product.price << "\n";
      total += product.price;
    }

    receipt << "\nTotal: ₩" << std::fixed << std::setprecision(2) << total
            << "\n";
    receipt.close();

    std::cout << "Order confirmed! Receipt saved as " << filename << "\n";

    cart.clear(); // Clear the cart after order is confirmed
  }
};

int main() {
  ShoppingMall mall;

  // Preprocessing
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

  int choice = 0;

  do {
    std::cout << "\n--- Shopping Mall Menu ---\n";
    std::cout << "1. View Products\n";
    std::cout << "2. Add to Cart\n";
    std::cout << "3. View Cart\n";
    std::cout << "4. Apply Coupon\n";
    std::cout << "5. Confirm Order\n";
    std::cout << "6. Exit\n";
    std::cout << "Enter your choice: ";
    std::cin >> choice;
    std::cout << "----------------------------------------------\n";

    switch (choice) {
    case 1:
      mall.viewProducts();
      break;
    case 2: {
      int productId;
      std::cout << "Enter product ID to add to cart: ";
      std::cin >> productId;
      mall.addToCart(productId);
      break;
    }
    case 3:
      mall.viewCart();
      break;
    case 4:
      mall.applyCoupon();
      break;
    case 5:
      mall.confirmOrder();
      break;
    case 6:
      std::cout << "Thank you for visiting the shopping mall!\n";
      break;
    default:
      std::cout << "Invalid choice. Please try again.\n";
    }
  } while (choice != 6);

  return 0;
}
