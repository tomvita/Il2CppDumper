ifeq ($(strip $(DEVKITPRO)),)
$(error "Please set DEVKITPRO in your environment. e.g. export DEVKITPRO=/opt/devkitpro")
endif

TOPDIR := $(CURDIR)
TARGET := switch_il2cpp_metadata
BUILD := build_switch
SOURCES := src
INCLUDES := include
ROMFS := romfs

include $(DEVKITPRO)/libnx/switch_rules
ELF2NRO ?= elf2nro

ARCH := -march=armv8-a+crc+crypto -mtune=cortex-a57 -mtp=soft -fPIE
WARN := -Wall -Wextra -Wpedantic

CFLAGS := -O2 -g $(WARN) $(ARCH) -ffunction-sections -fdata-sections
CXXFLAGS := $(CFLAGS) -std=gnu++17 -D__SWITCH__
ASFLAGS := -g $(ARCH)
LDFLAGS := -specs=$(DEVKITPRO)/libnx/switch.specs $(ARCH) -Wl,-Map,$(TARGET).map -Wl,--gc-sections
LIBS := -lnx
LOCAL_INCLUDE := $(foreach dir,$(INCLUDES),-I$(dir)) -I$(DEVKITPRO)/libnx/include
LIBNX_LIBDIR := $(DEVKITPRO)/libnx/lib
PORTLIBS_LIBDIR := $(DEVKITPRO)/portlibs/switch/lib
PORTLIBS_INCLUDEDIR := $(DEVKITPRO)/portlibs/switch/include
LOCAL_LIBPATHS := -L$(LIBNX_LIBDIR)
ifneq ($(wildcard $(PORTLIBS_LIBDIR)),)
LOCAL_LIBPATHS += -L$(PORTLIBS_LIBDIR)
endif
ifneq ($(wildcard $(PORTLIBS_INCLUDEDIR)),)
LOCAL_INCLUDE += -I$(PORTLIBS_INCLUDEDIR)
endif

CPPFILES := $(foreach dir,$(SOURCES),$(wildcard $(dir)/*.cpp))
OFILES := $(patsubst %.cpp,$(BUILD)/%.o,$(CPPFILES))

NRO := $(TARGET).nro
ELF := $(TARGET).elf

ifneq ($(wildcard $(ROMFS)),)
NROFLAGS += --romfsdir=$(ROMFS)
endif

.PHONY: all clean run

all: $(NRO)

$(NRO): $(ELF)
	@echo "  NRO     $@"
	@$(ELF2NRO) $< $@ $(NROFLAGS)

$(ELF): $(OFILES)
	@echo "  LD      $@"
	@if [ ! -f "$(LIBNX_LIBDIR)/libnx.a" ]; then \
		echo "ERROR: libnx not found at $(LIBNX_LIBDIR)/libnx.a"; \
		echo "Install libnx with devkitPro pacman (e.g. dkp-pacman -S switch-libnx)."; \
		exit 1; \
	fi
	@$(CXX) $(OFILES) $(LDFLAGS) $(LOCAL_LIBPATHS) $(LIBPATHS) $(LIBS) -o $@

$(BUILD)/%.o: %.cpp
	@mkdir -p $(dir $@)
	@echo "  CXX     $<"
	@$(CXX) $(CXXFLAGS) $(LOCAL_INCLUDE) -MMD -MP -c $< -o $@

run: $(NRO)
	@echo "Copy $(NRO) to /switch/$(TARGET)/$(NRO) on SD card."

clean:
	@echo "Cleaning Switch build artifacts..."
	@rm -rf $(BUILD) $(ELF) $(NRO) $(TARGET).map

-include $(OFILES:.o=.d)
