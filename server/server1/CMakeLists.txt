# CMakeList.txt: server1 的 CMake 项目，在此处包括源代码并定义
# 项目特定的逻辑。
#
cmake_minimum_required (VERSION 3.8)

# 将源代码添加到此项目的可执行文件。
add_executable(${PROJECT_NAME} "server1.cpp" "server1.h" "database.h" "database.cpp" 
                                "main.cpp" "MyDefine.h" "MyHttpCmdDef.h" "CMyHttpServer.h"
                                "CMyHttpServer.cpp" "MyHeader.h" "cryptogram.h" "cryptogram.cpp" 
                                "ThreadPool.h" "network.h" "network.cpp" "logger.h" "logger.cpp"
                                "http.h" "http.cpp" "serverbroker.cpp" "serverbroker.h" 
                                "define.h" )

find_package(OpenSSL REQUIRED)


if(WIN32)
set(BOOST_ROOT d:/lib/boost)
set(Boost_LIBRARY_DIRS d:/lib/boost/lib)
 
find_package(Boost 1.80 REQUIRED COMPONENTS system filesystem thread log)

else()
find_package(Boost 1.74 REQUIRED COMPONENTS system filesystem thread log)
endif()

if(Boost_FOUND)
    include_directories(${Boost_INCLUDE_DIRS})
    
    MESSAGE( STATUS "Boost_INCLUDE_DIRS = ${Boost_INCLUDE_DIRS}.")
    MESSAGE( STATUS "Boost_LIBRARIES = ${Boost_LIBRARIES}.")
    MESSAGE( STATUS "Boost_LIB_VERSION = ${Boost_LIB_VERSION}.")
endif()

if(OPENSSL_FOUND)
  include_directories(${OPENSSL_INCLUDE_DIRS})
  message(STATUS "OpenSSL Found!")
endif()

if (CMAKE_VERSION VERSION_GREATER 3.12)
  set_property(TARGET server1 PROPERTY CXX_STANDARD 20)
endif()

# TODO: 如有需要，请添加测试并安装目标。
if(WIN32) # 如果在Win下编译
    set(MYSQL_CONNECTOR_DIR "D:/lib/mysql") # 设置mysql的目录
    set(EVENT_DIR "D:/lib/libevent")
    set(MYSQL_LIB ${MYSQL_CONNECTOR_DIR}/lib/libmysql.lib) # 设置lib  )
    set(EVENT_LIB ${EVENT_DIR}/lib/event.lib ${EVENT_DIR}/lib/event_core.lib ${EVENT_DIR}/lib/event_extra.lib)
else() # Linux下编译

endif()

if(WIN32)
include_directories(${MYSQL_CONNECTOR_DIR}/include ${EVENT_DIR}/include "D:/lib/json-develop/include" "D:/lib/jwt-cpp-master/include" ${Boost_LIBRARIES}) # 添加头文件目录
else()
include_directories(${MYSQL_CONNECTOR_DIR}/include ${EVENT_DIR}/include /usr/include/nlohmann /usr/include/jwt-cpp-master/include ${Boost_LIBRARIES}) # 添加头文件目录
endif()
# 指定生成可执行文件

if(WIN32)
    target_link_libraries(${PROJECT_NAME}
        ${MYSQL_LIB} # 添加lib
        ${EVENT_LIB}
        OpenSSL::SSL 
        OpenSSL::Crypto
        ${Boost_LIBRARIES}
        )
else()
    target_link_libraries(${PROJECT_NAME}
        mysqlclient
        event
        event_pthreads
        OpenSSL::SSL
        OpenSSL::Crypto
        ${Boost_LIBRARIES}
        )
endif()

