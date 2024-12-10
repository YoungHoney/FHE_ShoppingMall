cmake_minimum_required(VERSION 3.10)
project(FHE_ShoppingMall)

# Include directories
include_directories(
    /usr/local/include/openfhe
    /usr/local/include/openfhe/pke
    /usr/local/include/openfhe/binfhe
    /usr/local/include/openfhe/core
)

# Link directories
link_directories(/usr/local/lib)

# Add executable
add_executable(FHE_ShoppingMall main.cpp)

# Link libraries
target_link_libraries(FHE_ShoppingMall 
    OPENFHEpke 
    OPENFHEbinfhe 
    OPENFHEcore
)


