cmake_minimum_required(VERSION 3.15 FATAL_ERROR)

project(gamayun CXX C)

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

set(GAMAYUN_SOURCES
    src/analysis/pattern_gen.cpp
    src/lumina/apply.cpp
    src/lumina/client.cpp
    src/lumina/metadata.cpp
    src/lumina/protocol.cpp
    src/lumina/pulled_metadata.cpp
    src/lumina/session.cpp
    src/lumina/settings.cpp
    src/lumina/type_decoder.cpp
    src/plugin/plugin.cpp
    src/ui/dialogs/lumina_bulk_diff_dialog.cpp
    src/ui/gamayun/gamayun_model.cpp
    src/ui/gamayun/gamayun_table_view.cpp
    src/ui/gamayun/gamayun_widget.cpp
)

set(GAMAYUN_HEADERS
    src/analysis/pattern_gen.h
    src/debug/debug_dump.h
    src/lumina/apply.h
    src/lumina/client.h
    src/lumina/codec.h
    src/lumina/metadata.h
    src/lumina/protocol.h
    src/lumina/pulled_metadata.h
    src/lumina/session.h
    src/lumina/settings.h
    src/lumina/type_decoder.h
    src/ui/dialogs/lumina_bulk_diff_dialog.h
    src/ui/gamayun/gamayun.h
)

add_library(gamayun SHARED
    ${GAMAYUN_SOURCES}
    ${GAMAYUN_HEADERS}
)

source_group(TREE ${CMAKE_CURRENT_SOURCE_DIR}/src FILES ${GAMAYUN_SOURCES} ${GAMAYUN_HEADERS})

if(NOT BN_API_BUILD_EXAMPLES AND NOT BN_INTERNAL_BUILD)
    find_path(
        BN_API_PATH
        NAMES binaryninjaapi.h
        HINTS ../.. binaryninja-api $ENV{BN_API_PATH}
        REQUIRED
    )
    add_subdirectory(${BN_API_PATH} api)
endif()

target_include_directories(gamayun PRIVATE
    ${BN_API_PATH}
    ${BN_API_PATH}/vendor/fmt/include
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CAPSTONE_INCLUDE_DIR}
)

target_link_libraries(gamayun
    binaryninjaui
    ${CAPSTONE_LIBRARY}
    Qt6::Core
    Qt6::Gui
    Qt6::Widgets
    Qt6::Network
)

target_compile_definitions(gamayun PRIVATE
    QT_NO_VERSION_TAGGING
    FMT_USE_CONSTEVAL=0
    FMT_HEADER_ONLY=1
    GAMAYUN_BUILD_QT_VERSION=\"${Qt6_VERSION}\"
    GAMAYUN_BUILD_QT_PLUGIN_PATH=\"${QT6_ROOT_PATH}/plugins\"
)

if(APPLE)
    set(BN_MACOS_RPATH "@executable_path")
    set(BN_QT_RPATH "@executable_path/../Frameworks")
    set_target_properties(gamayun PROPERTIES
        BUILD_WITH_INSTALL_RPATH ON
        BUILD_RPATH "${BN_MACOS_RPATH};${BN_QT_RPATH}"
        INSTALL_RPATH "${BN_MACOS_RPATH};${BN_QT_RPATH}"
        INSTALL_RPATH_USE_LINK_PATH FALSE)
endif()

set_target_properties(gamayun PROPERTIES
    CXX_STANDARD 20
    CXX_VISIBILITY_PRESET hidden
    CXX_STANDARD_REQUIRED ON
    VISIBILITY_INLINES_HIDDEN ON
    POSITION_INDEPENDENT_CODE ON
    LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/out/bin)

if(UNIX AND NOT APPLE)
    target_link_options(gamayun PRIVATE
        "$<$<CXX_COMPILER_ID:GNU,Clang>:-Wl,--version-script,${CMAKE_CURRENT_SOURCE_DIR}/qt_compat.ld>")
endif()

if(BN_INTERNAL_BUILD)
    ui_plugin_rpath(gamayun)
endif()

bn_install_plugin(${PROJECT_NAME})
