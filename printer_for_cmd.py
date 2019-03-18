
# !/usr/bin/env python
# encoding: utf-8
import ctypes

STD_INPUT_HANDLE = -10
STD_OUTPUT_HANDLE = -11
STD_ERROR_HANDLE = -12

FOREGROUND_BLACK = 0x0
FOREGROUND_BLUE = 0x01  # text color contains blue.
FOREGROUND_GREEN = 0x02  # text color contains green.
FOREGROUND_RED = 0x04  # text color contains red.
FOREGROUND_INTENSITY = 0x08  # text color is intensified.
FOREGROUND_YELLOW = 0x0e  # text color contains yellow

BACKGROUND_BLUE = 0x10  # background color contains blue.
BACKGROUND_GREEN = 0x20  # background color contains green.
BACKGROUND_RED = 0x40  # background color contains red.
BACKGROUND_INTENSITY = 0x80  # background color is intensified.


class Color:
    std_out_handle = ctypes.windll.kernel32.GetStdHandle(STD_OUTPUT_HANDLE)

    def set_cmd_color(self, color, handle=std_out_handle):
        """(color) -> bit
        Example: set_cmd_color(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY)
        """
        bool = ctypes.windll.kernel32.SetConsoleTextAttribute(handle, color)
        return bool

    def reset_color(self):
        self.set_cmd_color(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE)

    def print_red_text(self, print_text):
        self.set_cmd_color(FOREGROUND_RED | FOREGROUND_INTENSITY)
        print(print_text)
        self.reset_color()

    def print_green_text(self, print_text):
        self.set_cmd_color(FOREGROUND_GREEN | FOREGROUND_INTENSITY)
        print(print_text)
        self.reset_color()

    def print_blue_text(self, print_text):
        self.set_cmd_color(FOREGROUND_BLUE | FOREGROUND_INTENSITY)
        print(print_text)
        self.reset_color()

    def print_yellow_text(self, print_text):
        self.set_cmd_color(FOREGROUND_YELLOW | FOREGROUND_INTENSITY)
        print(print_text)
        self.reset_color()


clr = Color()


def print_warning(s):
    """
    打印警告信息，用黄色高亮方式显示
    :param s: 打印字符串
    :return:
    """
    clr.print_yellow_text("Warning: " + s)


def print_error(s):
    """
    打印错误信息，用红色高亮方式显示
    :param s: 打印字符串
    :return:
    """
    clr.print_red_text("Error: " + s)


def print_info(s):
    """
    打印通知信息，用蓝色高亮方式显示
    :param s: 打印字符串
    :return:
    """
    clr.print_blue_text(s)


def print_success(s):
    """
    打印成功信息，用绿色高亮方式显示
    :param s: 打印字符串
    :return:
    """
    clr.print_green_text(s)


def print_status(key, value):
    """
    打印状态信息
    :param key: string
    :param value: boolean
    :return:
    """
    print(key + ": ", end='')
    if value:
        clr.print_green_text("Yes")
    else:
        clr.print_red_text("No")


if __name__ == '__main__':
    print_warning("this is a test")
    print_error("this is a test")
