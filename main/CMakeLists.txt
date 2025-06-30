idf_component_register(SRCS "esp32_nat_router.c"
                            "http_server.c"
                    INCLUDE_DIRS "."
                    EMBED_FILES "../www/index.html"
                    REQUIRES json esp_wifi console nvs_flash esp_timer esp_http_server
                             cmd_system cmd_nvs cmd_router driver spi_flash vfs fatfs
                             esp_netif lwip pthread wpa_supplicant freertos)

set_source_files_properties(http_server.c
    PROPERTIES COMPILE_FLAGS
    -Wno-unused-function
)
