cmake_minimum_required(VERSION 3.16)
project(MetadataWorker VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

option(BUILD_CLI "Build CLI version" ON)
option(Build_GUI "Build GUI version (requires Qt)" OFF)
option(USE_SYSTEM_ELFIO "Use system elfio library" OFF)

set(SOURCES
    src/cli_main.cpp
    src/metadata.cpp
    src/decryptor.cpp
    src/config.cpp
    src/i18n.cpp
    src/utils.cpp
)

set(HEADERS
    include/metadata.hpp
    include/decryptor.hpp
    include/config.hpp
    include/i18n.hpp
    include/utils.hpp
    include/types.hpp
)

add_library(metadata_worker_lib STATIC ${SOURCES} ${HEADERS})
target_include_directories(metadata_worker_lib PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)

if(WIN32)
    target_compile_definitions(metadata_worker_lib PRIVATE _CRT_SECURE_NO_WARNINGS)
elseif(UNIX AND NOT APPLE)
    target_compile_definitions(metadata_worker_lib PRIVATE __LINUX__)
endif()

if(BUILD_CLI)
    add_executable(metadata_worker_cli src/cli_main.cpp)
    target_link_libraries(metadata_worker_cli PRIVATE metadata_worker_lib)
    set_target_properties(metadata_worker_cli PROPERTIES OUTPUT_NAME "metadata-worker")
    
    if(MSVC)
        target_compile_options(metadata_worker_cli PRIVATE /MT$<$<CONFIG:Debug>:d>)
        target_link_options(metadata_worker_cli PRIVATE /STATIC)
    elseif(MINGW)
        target_link_options(metadata_worker_cli PRIVATE -static-libgcc -static-libstdc++)
    endif()
endif()

if(Build_GUI)
    find_package(Qt6 COMPONENTS Widgets REQUIRED)
    add_executable(metadata_worker_gui 
        src/gui_main.cpp
        src/gui/mainwindow.cpp
        src/gui/mainwindow.ui
    )
    target_link_libraries(metadata_worker_gui PRIVATE 
        metadata_worker_lib 
        Qt6::Widgets
    )
    set_target_properties(metadata_worker_gui PROPERTIES OUTPUT_NAME "metadata-worker-gui")
endif()

option(BUILD_TESTS "Build tests" OFF)
if(BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

install(TARGETS metadata_worker_cli
    RUNTIME DESTINATION bin
)

install(DIRECTORY include/ DESTINATION include)
