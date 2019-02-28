import sys
import printer_for_cmd


def print_warning(s):
    """
    打印警告信息，用黄色高亮方式显示
    :param s: 打印字符串
    :return:
    """
    if sys.platform == 'win32':
        printer_for_cmd.print_warning(s)
    else:
        print("\033[1;33mWarning: " + s + "\033[0m")


def print_error(s):
    """
    打印错误信息，用红色高亮方式显示
    :param s: 打印字符串
    :return:
    """
    if sys.platform == 'win32':
        printer_for_cmd.print_error(s)
    else:
        print("\033[1;31mError: " + s + "\033[0m")


def print_info(s):
    """
    打印通知信息，用蓝色高亮方式显示
    :param s: 打印字符串
    :return:
    """
    if sys.platform == 'win32':
        printer_for_cmd.print_info(s)
    else:
        print("\033[1;34m" + s + "\033[0m")


def print_success(s):
    """
    打印成功信息，用绿色高亮方式显示
    :param s: 打印字符串
    :return:
    """
    if sys.platform == 'win32':
        printer_for_cmd.print_success(s)
    else:
        print("\033[1;32m" + s + "\033[0m")


def print_status(key, value):
    """
    打印状态信息
    :param key: string
    :param value: boolean
    :return:
    """
    if sys.platform == 'win32':
        printer_for_cmd.print_status(key, value)
    else:
        print(key + ": ", end='')
        if value:
            print("\033[1;34mYes\033[0m")
        else:
            print("\033[1;31mNo\033[0m")


if __name__ == '__main__':
    print_warning("this is a test")
    print_error("this is a test")
