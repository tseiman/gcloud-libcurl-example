
cmake_minimum_required(VERSION 3.1...3.28)

project(
    gcloud-libcurl-example
    VERSION 1.0
    LANGUAGES C)


set(SOURCES
  src/main.c
  src/alloc.c
  src/htmlClient.c
  src/readJSON.c
  src/javaWebToken.c
  src/base64url.c
  src/dataSource.c
)
add_executable(gcloud-libcurl-example ${SOURCES})


set(CMAKE_MODULE_PATH
  ${CMAKE_CURRENT_SOURCE_DIR}/cmake
)

# target_compile_options(gcloud-libcurl-example PUBLIC -fmacro-prefix-map=../src/=)

find_package(OpenSSL REQUIRED)
set(CMAKE_REQUIRED_INCLUDES ${OPENSSL_INCLUDE_DIR})
set(CMAKE_REQUIRED_LIBRARIES OpenSSL::Crypto OpenSSL::SSL)
target_link_libraries(gcloud-libcurl-example ssl crypto)


find_package(CURL REQUIRED)
include_directories(${CURL_INCLUDE_DIRS})
target_link_libraries(gcloud-libcurl-example ${CURL_LIBRARIES})

include_directories(include)





find_package(PlantUML)
if(DEFINED PlantUML)
  set(DOCS
    ../docs/sequence.uml
  )
  add_custom_target(DOCS ALL
      WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}/doc
      DEPENDS ${PROJECT_SOURCE_DIR}/doc/sequence.svg
      COMMENT "DOCS target"
      VERBATIM
  )

  add_custom_command(
    OUTPUT
      ../doc/sequence.svg
    COMMAND
      ${PlantUML} ${PROJECT_SOURCE_DIR}/doc/sequence.uml -darkmode -tsvg
    WORKING_DIRECTORY
      ${PROJECT_SOURCE_DIR}/doc
    DEPENDS
      ${DOC_SRCS}
    
    )
endif()

