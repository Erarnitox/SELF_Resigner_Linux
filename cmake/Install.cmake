install(TARGETS resigner eboot_diff
    RUNTIME DESTINATION .
    COMPONENT ps3_tools
)

install(DIRECTORY "${CMAKE_SOURCE_DIR}/res/data/"
    DESTINATION data
    COMPONENT ps3_tools
)

install(FILES "${CMAKE_SOURCE_DIR}/res/icons/app_icon.png"
    DESTINATION data/icons
    COMPONENT ps3_tools
)

if(EXISTS "${CMAKE_SOURCE_DIR}/README.MD")
    install(FILES "${CMAKE_SOURCE_DIR}/README.MD"
        DESTINATION .
        COMPONENT ps3_tools
    )
endif()
