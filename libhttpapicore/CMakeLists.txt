set(SOURCES
    HttpApiServer.h HttpApiServer.cpp
)

add_library(httpapicore ${SOURCES})
target_link_libraries(httpapicore PRIVATE ethcore devcore kawpowminer-buildinfo Boost::filesystem)
target_include_directories(httpapicore PRIVATE ..)
