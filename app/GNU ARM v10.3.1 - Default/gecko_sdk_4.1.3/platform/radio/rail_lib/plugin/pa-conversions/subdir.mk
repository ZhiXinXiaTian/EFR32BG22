################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
C_SRCS += \
E:/SimplicityStudio/SDKs/gecko_sdk/platform/radio/rail_lib/plugin/pa-conversions/pa_conversions_efr32.c \
E:/SimplicityStudio/SDKs/gecko_sdk/platform/radio/rail_lib/plugin/pa-conversions/pa_curves_efr32.c 

OBJS += \
./gecko_sdk_4.1.3/platform/radio/rail_lib/plugin/pa-conversions/pa_conversions_efr32.o \
./gecko_sdk_4.1.3/platform/radio/rail_lib/plugin/pa-conversions/pa_curves_efr32.o 

C_DEPS += \
./gecko_sdk_4.1.3/platform/radio/rail_lib/plugin/pa-conversions/pa_conversions_efr32.d \
./gecko_sdk_4.1.3/platform/radio/rail_lib/plugin/pa-conversions/pa_curves_efr32.d 


# Each subdirectory must supply rules for building sources it contributes
gecko_sdk_4.1.3/platform/radio/rail_lib/plugin/pa-conversions/pa_conversions_efr32.o: E:/SimplicityStudio/SDKs/gecko_sdk/platform/radio/rail_lib/plugin/pa-conversions/pa_conversions_efr32.c gecko_sdk_4.1.3/platform/radio/rail_lib/plugin/pa-conversions/subdir.mk
	@echo 'Building file: $<'
	@echo 'Invoking: GNU ARM C Compiler'
	arm-none-eabi-gcc -g3 -gdwarf-2 -mcpu=cortex-m33 -mthumb -std=c99 '-DEFR32BG22C112F352GM32=1' '-DSL_APP_PROPERTIES=1' '-DBOOTLOADER_APPLOADER=1' '-DSL_COMPONENT_CATALOG_PRESENT=1' '-DMBEDTLS_CONFIG_FILE=<mbedtls_config.h>' '-DMBEDTLS_PSA_CRYPTO_CONFIG_FILE=<psa_crypto_config.h>' '-DSL_RAIL_LIB_MULTIPROTOCOL_SUPPORT=0' '-DSL_RAIL_UTIL_PA_CONFIG_HEADER=<sl_rail_util_pa_config.h>' '-DSLI_RADIOAES_REQUIRES_MASKING=1' -I"C:\Users\Xin\SimplicityStudio\v5_workspace\bt_soc_empty\config" -I"C:\Users\Xin\SimplicityStudio\v5_workspace\bt_soc_empty" -I"E:/SimplicityStudio/SDKs/gecko_sdk//platform/Device/SiliconLabs/EFR32BG22/Include" -I"E:/SimplicityStudio/SDKs/gecko_sdk//app/common/util/app_assert" -I"E:/SimplicityStudio/SDKs/gecko_sdk//protocol/bluetooth/inc" -I"E:/SimplicityStudio/SDKs/gecko_sdk//platform/common/inc" -I"E:/SimplicityStudio/SDKs/gecko_sdk//platform/bootloader" -I"E:/SimplicityStudio/SDKs/gecko_sdk//platform/bootloader/api" -I"E:/SimplicityStudio/SDKs/gecko_sdk//platform/CMSIS/Core/Include" -I"E:/SimplicityStudio/SDKs/gecko_sdk//util/third_party/crypto/sl_component/sl_cryptoacc_library/include" -I"E:/SimplicityStudio/SDKs/gecko_sdk//util/third_party/crypto/sl_component/sl_cryptoacc_library/src" -I"E:/SimplicityStudio/SDKs/gecko_sdk//platform/service/device_init/inc" -I"E:/SimplicityStudio/SDKs/gecko_sdk//platform/emdrv/dmadrv/inc" -I"E:/SimplicityStudio/SDKs/gecko_sdk//platform/emdrv/common/inc" -I"E:/SimplicityStudio/SDKs/gecko_sdk//platform/emlib/inc" -I"E:/SimplicityStudio/SDKs/gecko_sdk//platform/emdrv/gpiointerrupt/inc" -I"E:/SimplicityStudio/SDKs/gecko_sdk//platform/service/hfxo_manager/inc" -I"E:/SimplicityStudio/SDKs/gecko_sdk//app/bluetooth/common/in_place_ota_dfu" -I"E:/SimplicityStudio/SDKs/gecko_sdk//util/third_party/crypto/sl_component/sl_mbedtls_support/config" -I"E:/SimplicityStudio/SDKs/gecko_sdk//util/third_party/crypto/sl_component/sl_mbedtls_support/inc" -I"E:/SimplicityStudio/SDKs/gecko_sdk//util/third_party/crypto/mbedtls/include" -I"E:/SimplicityStudio/SDKs/gecko_sdk//util/third_party/crypto/mbedtls/library" -I"E:/SimplicityStudio/SDKs/gecko_sdk//platform/service/mpu/inc" -I"E:/SimplicityStudio/SDKs/gecko_sdk//platform/emdrv/nvm3/inc" -I"E:/SimplicityStudio/SDKs/gecko_sdk//platform/service/power_manager/inc" -I"E:/SimplicityStudio/SDKs/gecko_sdk//util/third_party/crypto/sl_component/sl_psa_driver/inc" -I"E:/SimplicityStudio/SDKs/gecko_sdk//util/third_party/crypto/sl_component/sl_psa_driver/inc/public" -I"E:/SimplicityStudio/SDKs/gecko_sdk//platform/radio/rail_lib/common" -I"E:/SimplicityStudio/SDKs/gecko_sdk//platform/radio/rail_lib/protocol/ble" -I"E:/SimplicityStudio/SDKs/gecko_sdk//platform/radio/rail_lib/protocol/ieee802154" -I"E:/SimplicityStudio/SDKs/gecko_sdk//platform/radio/rail_lib/protocol/zwave" -I"E:/SimplicityStudio/SDKs/gecko_sdk//platform/radio/rail_lib/chip/efr32/efr32xg2x" -I"E:/SimplicityStudio/SDKs/gecko_sdk//platform/radio/rail_lib/plugin/pa-conversions" -I"E:/SimplicityStudio/SDKs/gecko_sdk//platform/radio/rail_lib/plugin/pa-conversions/efr32xg22" -I"E:/SimplicityStudio/SDKs/gecko_sdk//platform/radio/rail_lib/plugin/rail_util_pti" -I"E:/SimplicityStudio/SDKs/gecko_sdk//util/third_party/crypto/sl_component/se_manager/inc" -I"E:/SimplicityStudio/SDKs/gecko_sdk//util/third_party/crypto/sl_component/se_manager/src" -I"E:/SimplicityStudio/SDKs/gecko_sdk//util/silicon_labs/silabs_core/memory_manager" -I"E:/SimplicityStudio/SDKs/gecko_sdk//platform/common/toolchain/inc" -I"E:/SimplicityStudio/SDKs/gecko_sdk//platform/service/system/inc" -I"E:/SimplicityStudio/SDKs/gecko_sdk//platform/service/sleeptimer/inc" -I"E:/SimplicityStudio/SDKs/gecko_sdk//util/third_party/crypto/sl_component/sl_protocol_crypto/src" -I"E:/SimplicityStudio/SDKs/gecko_sdk//platform/emdrv/uartdrv/inc" -I"C:\Users\Xin\SimplicityStudio\v5_workspace\bt_soc_empty\autogen" -Os -Wall -Wextra -ffunction-sections -fdata-sections -imacrossl_gcc_preinclude.h -mfpu=fpv5-sp-d16 -mfloat-abi=hard -mcmse -c -fmessage-length=0 -MMD -MP -MF"gecko_sdk_4.1.3/platform/radio/rail_lib/plugin/pa-conversions/pa_conversions_efr32.d" -MT"$@" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '

gecko_sdk_4.1.3/platform/radio/rail_lib/plugin/pa-conversions/pa_curves_efr32.o: E:/SimplicityStudio/SDKs/gecko_sdk/platform/radio/rail_lib/plugin/pa-conversions/pa_curves_efr32.c gecko_sdk_4.1.3/platform/radio/rail_lib/plugin/pa-conversions/subdir.mk
	@echo 'Building file: $<'
	@echo 'Invoking: GNU ARM C Compiler'
	arm-none-eabi-gcc -g3 -gdwarf-2 -mcpu=cortex-m33 -mthumb -std=c99 '-DEFR32BG22C112F352GM32=1' '-DSL_APP_PROPERTIES=1' '-DBOOTLOADER_APPLOADER=1' '-DSL_COMPONENT_CATALOG_PRESENT=1' '-DMBEDTLS_CONFIG_FILE=<mbedtls_config.h>' '-DMBEDTLS_PSA_CRYPTO_CONFIG_FILE=<psa_crypto_config.h>' '-DSL_RAIL_LIB_MULTIPROTOCOL_SUPPORT=0' '-DSL_RAIL_UTIL_PA_CONFIG_HEADER=<sl_rail_util_pa_config.h>' '-DSLI_RADIOAES_REQUIRES_MASKING=1' -I"C:\Users\Xin\SimplicityStudio\v5_workspace\bt_soc_empty\config" -I"C:\Users\Xin\SimplicityStudio\v5_workspace\bt_soc_empty" -I"E:/SimplicityStudio/SDKs/gecko_sdk//platform/Device/SiliconLabs/EFR32BG22/Include" -I"E:/SimplicityStudio/SDKs/gecko_sdk//app/common/util/app_assert" -I"E:/SimplicityStudio/SDKs/gecko_sdk//protocol/bluetooth/inc" -I"E:/SimplicityStudio/SDKs/gecko_sdk//platform/common/inc" -I"E:/SimplicityStudio/SDKs/gecko_sdk//platform/bootloader" -I"E:/SimplicityStudio/SDKs/gecko_sdk//platform/bootloader/api" -I"E:/SimplicityStudio/SDKs/gecko_sdk//platform/CMSIS/Core/Include" -I"E:/SimplicityStudio/SDKs/gecko_sdk//util/third_party/crypto/sl_component/sl_cryptoacc_library/include" -I"E:/SimplicityStudio/SDKs/gecko_sdk//util/third_party/crypto/sl_component/sl_cryptoacc_library/src" -I"E:/SimplicityStudio/SDKs/gecko_sdk//platform/service/device_init/inc" -I"E:/SimplicityStudio/SDKs/gecko_sdk//platform/emdrv/dmadrv/inc" -I"E:/SimplicityStudio/SDKs/gecko_sdk//platform/emdrv/common/inc" -I"E:/SimplicityStudio/SDKs/gecko_sdk//platform/emlib/inc" -I"E:/SimplicityStudio/SDKs/gecko_sdk//platform/emdrv/gpiointerrupt/inc" -I"E:/SimplicityStudio/SDKs/gecko_sdk//platform/service/hfxo_manager/inc" -I"E:/SimplicityStudio/SDKs/gecko_sdk//app/bluetooth/common/in_place_ota_dfu" -I"E:/SimplicityStudio/SDKs/gecko_sdk//util/third_party/crypto/sl_component/sl_mbedtls_support/config" -I"E:/SimplicityStudio/SDKs/gecko_sdk//util/third_party/crypto/sl_component/sl_mbedtls_support/inc" -I"E:/SimplicityStudio/SDKs/gecko_sdk//util/third_party/crypto/mbedtls/include" -I"E:/SimplicityStudio/SDKs/gecko_sdk//util/third_party/crypto/mbedtls/library" -I"E:/SimplicityStudio/SDKs/gecko_sdk//platform/service/mpu/inc" -I"E:/SimplicityStudio/SDKs/gecko_sdk//platform/emdrv/nvm3/inc" -I"E:/SimplicityStudio/SDKs/gecko_sdk//platform/service/power_manager/inc" -I"E:/SimplicityStudio/SDKs/gecko_sdk//util/third_party/crypto/sl_component/sl_psa_driver/inc" -I"E:/SimplicityStudio/SDKs/gecko_sdk//util/third_party/crypto/sl_component/sl_psa_driver/inc/public" -I"E:/SimplicityStudio/SDKs/gecko_sdk//platform/radio/rail_lib/common" -I"E:/SimplicityStudio/SDKs/gecko_sdk//platform/radio/rail_lib/protocol/ble" -I"E:/SimplicityStudio/SDKs/gecko_sdk//platform/radio/rail_lib/protocol/ieee802154" -I"E:/SimplicityStudio/SDKs/gecko_sdk//platform/radio/rail_lib/protocol/zwave" -I"E:/SimplicityStudio/SDKs/gecko_sdk//platform/radio/rail_lib/chip/efr32/efr32xg2x" -I"E:/SimplicityStudio/SDKs/gecko_sdk//platform/radio/rail_lib/plugin/pa-conversions" -I"E:/SimplicityStudio/SDKs/gecko_sdk//platform/radio/rail_lib/plugin/pa-conversions/efr32xg22" -I"E:/SimplicityStudio/SDKs/gecko_sdk//platform/radio/rail_lib/plugin/rail_util_pti" -I"E:/SimplicityStudio/SDKs/gecko_sdk//util/third_party/crypto/sl_component/se_manager/inc" -I"E:/SimplicityStudio/SDKs/gecko_sdk//util/third_party/crypto/sl_component/se_manager/src" -I"E:/SimplicityStudio/SDKs/gecko_sdk//util/silicon_labs/silabs_core/memory_manager" -I"E:/SimplicityStudio/SDKs/gecko_sdk//platform/common/toolchain/inc" -I"E:/SimplicityStudio/SDKs/gecko_sdk//platform/service/system/inc" -I"E:/SimplicityStudio/SDKs/gecko_sdk//platform/service/sleeptimer/inc" -I"E:/SimplicityStudio/SDKs/gecko_sdk//util/third_party/crypto/sl_component/sl_protocol_crypto/src" -I"E:/SimplicityStudio/SDKs/gecko_sdk//platform/emdrv/uartdrv/inc" -I"C:\Users\Xin\SimplicityStudio\v5_workspace\bt_soc_empty\autogen" -Os -Wall -Wextra -ffunction-sections -fdata-sections -imacrossl_gcc_preinclude.h -mfpu=fpv5-sp-d16 -mfloat-abi=hard -mcmse -c -fmessage-length=0 -MMD -MP -MF"gecko_sdk_4.1.3/platform/radio/rail_lib/plugin/pa-conversions/pa_curves_efr32.d" -MT"$@" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


