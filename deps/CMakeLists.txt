cmake_minimum_required(VERSION 3.16)

##########
# Zycore #
##########
add_subdirectory(zycore-1.5.2)
set(ZYAN_ZYCORE_PATH "${CMAKE_CURRENT_LIST_DIR}/zycore-1.5.2" CACHE PATH "" FORCE)

#########
# Zydis #
#########
add_subdirectory(zydis-4.1.1)

set_target_properties(Zycore PROPERTIES FOLDER "Dependencies")
set_target_properties(Zydis PROPERTIES FOLDER "Dependencies")
