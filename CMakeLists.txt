
cmake_minimum_required(VERSION 3.1...3.28)

project(
    gcloud-libcurl-example
    VERSION 1.0
    LANGUAGES C)


set(SOURCES
  src/main.c
  src/htmlClient.c
  src/readJSON.c
  src/javaWebToken.c
  src/base64url.c
  src/dataSource.c
)
add_executable(gcloud-libcurl-example ${SOURCES})

# target_compile_options(gcloud-libcurl-example PUBLIC -fmacro-prefix-map=../src/=)

find_package(OpenSSL REQUIRED)
set(CMAKE_REQUIRED_INCLUDES ${OPENSSL_INCLUDE_DIR})
set(CMAKE_REQUIRED_LIBRARIES OpenSSL::Crypto OpenSSL::SSL)
target_link_libraries(gcloud-libcurl-example ssl crypto)

find_package(CURL REQUIRED)
include_directories(${CURL_INCLUDE_DIRS})
target_link_libraries(gcloud-libcurl-example ${CURL_LIBRARIES})

include_directories(include)



