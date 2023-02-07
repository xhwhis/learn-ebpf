TARGET_DIR = $(CURDIR)/target/debug

.PHONY: all
all: $(TARGET_DIR)/libdump.so $(TARGET_DIR)/main

.PHONY: clean
clean:
	cargo clean

$(TARGET_DIR)/libdump.so:
	cargo xtask build

$(TARGET_DIR)/main: main.c
	cc $< -o $@ -pthread -ldl -std=c11 -Wall -Wextra

.PHONY: test
test: $(TARGET_DIR)/main $(TARGET_DIR)/libdump.so
	sudo -E $?
