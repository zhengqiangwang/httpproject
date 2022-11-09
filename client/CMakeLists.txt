
if(WIN32)
    message(STATUS "win32-----------------------------------")
    FILE(GLOB PLATFORM_SOURCES *_win.cpp *.h)
    #set (Qt5_DIR D:\\Qt\\qt5.15_64\\msvc2019\\lib\\cmake\\Qt5)
    #set (OPENSSL_ROOT_DIR D:\\lib\\OpenSSL-Win64)
elseif(UNIX)
    message(STATUS "Linux")
    FILE(GLOB PLATFORM_SOURCES *_linux.cpp)
    set (Qt5_DIR /home/wang/Qt5.14.0/5.14.0/gcc_64/lib/cmake/Qt5)
elseif(IOS)
    FILE(GLOB PLATFORM_SOURCES *_ios.cpp)
elseif(ANDROID)
    FILE(GLOB PLATFORM_SOURCES *_android.cpp)
endif()


cmake_minimum_required(VERSION 3.8)

project(client_linux VERSION 0.1 LANGUAGES CXX)

set(CMAKE_INCLUDE_CURRENT_DIR ON)

set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)



# 将源代码添加到此项目的可执行文件。
add_executable (client_linux  client.ui main.cpp define.h client.h client.cpp userbroker.h 
		userbroker.cpp http.h http.cpp cryptogram.h cryptogram.cpp plainhttp.h 
		plainhttp.cpp curlhttp.h curlhttp.cpp)

target_include_directories(client_linux PRIVATE /usr/include/nlohmann)

find_package(Qt5 COMPONENTS Widgets REQUIRED)
find_package(OpenSSL REQUIRED)

if(OPENSSL_FOUND)
  include_directories(${OPENSSL_INCLUDE_DIRS})
  message(STATUS "OpenSSL Found!")
endif()

target_link_libraries(client_linux PRIVATE OpenSSL::SSL OpenSSL::Crypto Qt5::Core Qt5::Gui Qt5::Widgets curl)

#find_package(QT NAMES Qt6 Qt5 REQUIRED COMPONENTS Widgets)
#find_package(Qt${QT_VERSION_MAJOR} REQUIRED COMPONENTS Widgets)

#set(PROJECT_SOURCES
#        main.cpp
#        clienttest.cpp
#        clienttest.h
#        clienttest.ui
#)
#add_executable(CMakeclient
#            ${PROJECT_SOURCES}
#        )

#if(${QT_VERSION_MAJOR} GREATER_EQUAL 6)
#    qt_add_executable(CMakeclient
#        MANUAL_FINALIZATION
#        ${PROJECT_SOURCES}
#    )
# Define target properties for Android with Qt 6 as:
#    set_property(TARGET untitled1 APPEND PROPERTY QT_ANDROID_PACKAGE_SOURCE_DIR
#                 ${CMAKE_CURRENT_SOURCE_DIR}/android)
# For more information, see https://doc.qt.io/qt-6/qt-add-executable.html#target-creation
#else()
#    if(ANDROID)
#        add_library(CMakeclient SHARED
#            ${PROJECT_SOURCES}
#        )
# Define properties for Android with Qt 5 after find_package() calls as:
#    set(ANDROID_PACKAGE_SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/android")
#    else()
#        add_executable(CMakeclient
#            ${PROJECT_SOURCES}
#        )
#    endif()
#endif()

#target_link_libraries(CMakeclient PRIVATE Qt${QT_VERSION_MAJOR}::Widgets)

#set_target_properties(CMakeclient PROPERTIES
#    MACOSX_BUNDLE_GUI_IDENTIFIER my.example.com
#    MACOSX_BUNDLE_BUNDLE_VERSION ${PROJECT_VERSION}
#    MACOSX_BUNDLE_SHORT_VERSION_STRING ${PROJECT_VERSION_MAJOR}.${PROJECT_VERSION_MINOR}
#    MACOSX_BUNDLE TRUE
 #   WIN32_EXECUTABLE TRUE
#)

#if(QT_VERSION_MAJOR EQUAL 6)
#    qt_finalize_executable(CMakeclient)
#endif()

#SET(CMAKE_INSTALL_RPATH_USE_LINK_PATH TRUE)
