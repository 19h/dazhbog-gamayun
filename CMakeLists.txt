cmake_minimum_required(VERSION 3.15 FATAL_ERROR)

project(function_metadata_sidebar CXX C)

file(GLOB SOURCES
	*.cpp
	*.h)

# Enable Qt MOC
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)

if(APPLE)
    set(DEFAULT_QT6_ROOT_PATH "/Users/int/Qt-6.6.1")
else()
    set(DEFAULT_QT6_ROOT_PATH "/media/null/ares/qt/6.10.1/qtbase")
endif()

set(QT6_ROOT_PATH "${DEFAULT_QT6_ROOT_PATH}" CACHE PATH "Qt 6 installation root")

if(EXISTS "${QT6_ROOT_PATH}/lib/cmake")
    list(PREPEND CMAKE_PREFIX_PATH "${QT6_ROOT_PATH}/lib/cmake")
elseif(EXISTS "${QT6_ROOT_PATH}")
    list(PREPEND CMAKE_PREFIX_PATH "${QT6_ROOT_PATH}")
endif()

find_package(Qt6 6.6 COMPONENTS Core Gui Widgets Network REQUIRED)
message(STATUS "Using Qt ${Qt6_VERSION} from ${Qt6_DIR}")

find_path(CAPSTONE_INCLUDE_DIR capstone/capstone.h)
find_library(CAPSTONE_LIBRARY capstone)

if(NOT CAPSTONE_INCLUDE_DIR OR NOT CAPSTONE_LIBRARY)
    message(FATAL_ERROR "Capstone library not found")
endif()

add_library(function_metadata_sidebar SHARED
    ${SOURCES}
    lumina_client.cpp
    lumina_client.h
    lumina_codec.h
    lumina_metadata.cpp
    lumina_metadata.h
    lumina_protocol.cpp
    lumina_protocol.h
    pattern_gen.cpp
    pattern_gen.h
    lumina_settings.cpp
    lumina_settings.h
)

if(NOT BN_API_BUILD_EXAMPLES AND NOT BN_INTERNAL_BUILD)
    # Out-of-tree build
    find_path(
        BN_API_PATH
        NAMES binaryninjaapi.h
        HINTS ../.. binaryninja-api $ENV{BN_API_PATH}
        REQUIRED
    )
    add_subdirectory(${BN_API_PATH} api)
endif()

# Add include directories for Binary Ninja API headers
target_include_directories(function_metadata_sidebar PRIVATE
    ${BN_API_PATH}
    ${BN_API_PATH}/vendor/fmt/include
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CAPSTONE_INCLUDE_DIR})

# Link against binaryninjaui and Qt 6.8
# Since we're compiling with Qt 6.8 headers and linking Qt 6.8 libs,
# Binary Ninja's Qt 6.8 runtime will work correctly
target_link_libraries(function_metadata_sidebar 
    binaryninjaui
    ${CAPSTONE_LIBRARY}
    Qt6::Core 
    Qt6::Gui 
    Qt6::Widgets
    Qt6::Network)

# Disable Qt symbol versioning for maximum compatibility
# Also disable consteval in fmt which has issues with some clang versions
# FMT_HEADER_ONLY ensures fmt library is header-only
target_compile_definitions(function_metadata_sidebar PRIVATE
    QT_NO_VERSION_TAGGING
    FMT_USE_CONSTEVAL=0
    FMT_HEADER_ONLY=1)

if(APPLE)
    set(BN_MACOS_RPATH "@executable_path")
    set(BN_QT_RPATH "@executable_path/../Frameworks")
    set_target_properties(function_metadata_sidebar PROPERTIES
        BUILD_WITH_INSTALL_RPATH ON
        BUILD_RPATH "${BN_MACOS_RPATH};${BN_QT_RPATH}"
        INSTALL_RPATH "${BN_MACOS_RPATH};${BN_QT_RPATH}"
        INSTALL_RPATH_USE_LINK_PATH FALSE)
endif()

set_target_properties(function_metadata_sidebar PROPERTIES
    CXX_STANDARD 20
	CXX_VISIBILITY_PRESET hidden
	CXX_STANDARD_REQUIRED ON
    VISIBILITY_INLINES_HIDDEN ON
	POSITION_INDEPENDENT_CODE ON
	LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/out/bin)

if(UNIX AND NOT APPLE)
    target_link_options(function_metadata_sidebar PRIVATE
        "$<$<CXX_COMPILER_ID:GNU,Clang>:-Wl,--version-script,${CMAKE_CURRENT_SOURCE_DIR}/qt_compat.ld>")
endif()

if(BN_INTERNAL_BUILD)
	ui_plugin_rpath(function_metadata_sidebar)
endif()

bn_install_plugin(${PROJECT_NAME})
