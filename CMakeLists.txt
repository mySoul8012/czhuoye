cmake_minimum_required(VERSION 3.28)
project(untitled1)

# 设置 NPcap 库和头文件的路径
set(NPCAP_INCLUDE_DIR "C:/Program Files/Npcap/Include")
set(NPCAP_LIBRARIES "C:/Program Files/Npcap/Lib/x64/wpcap.lib")

# 设置Qt库的路径
set(Qt6_DIR "C:/Qt/6.7.2/mingw_64/lib/cmake/Qt6")

# 查找Qt库
find_package(Qt6 COMPONENTS Widgets REQUIRED)


# 添加 include 目录
include_directories(${NPCAP_INCLUDE_DIR})

# 源文件
set(SOURCE_FILES
        main.cpp
        ARPCap.cpp
        ARPCap.h
        MainWindow.cpp
        MainWindow.h
)

# 启用moc、uic和rcc
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTORCC ON)

# 创建可执行文件
add_executable(untitled1 ${SOURCE_FILES})

# 链接 NPcap 和 ws2_32 库
target_link_libraries(untitled1 ${NPCAP_LIBRARIES} ws2_32 iphlpapi Qt6::Widgets)

# 配置日志文件路径
target_compile_definitions(untitled1 PRIVATE LOG_FILE="${CMAKE_CURRENT_SOURCE_DIR}/logfile.txt")
