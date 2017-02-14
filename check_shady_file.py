# -*- coding: utf-8 -*-

u"""怪しいファイルを検索します.

指定したディレクトリ配下に存在する怪しいファイル(攻撃コード)を検索し列挙します。
ホワイトリストに記載されているファイルは対象外とします。
判定方法:
    * スキャンパターン1:特定の文字列の有無
    * スキャンパターン2:特定の文字列の出現数(一定以上の件数)
使用方法:
    python check_shady_file.py <Scan Directory path>
"""

from ast import literal_eval
import os
import os.path
import subprocess
import sys

import common_util
import mail_util


class CheckShadyFile(object):
    u"""指定したディレクトリ配下に怪しいファイルが存在するかスキャンします."""

    # スキャン対象外ファイルを列挙したファイル名(ホワイトリスト)
    IGNORE_FILE_NAME = './ignore.conf'
    # スキャン対象外のファイル
    IGNORE_FILE_LIST = {}
    # スキャン対象外のファイル拡張子
    IGNORE_FILE_EXT = []
    # スキャン結果
    RESULTS = []
    # スキャン1で検索対象の文字列
    SCAN1_WORD = []
    # スキャン2で使用する対象文字列としきい値
    SCAN2_WORD_DICT = {}
    # スキャン結果の出力内容から除外する拡張子
    OUTPUT_FILE_EXT = []

    # 汎用ユーティリティクラス
    __CU = common_util.CommonUtil()
    # メール送信ユーティリティクラス
    # __MU = mail_util.MailUtil()

    def __init__(self):
        u"""初期処理."""
        # スキャン対象のディレクトリ
        self.target_dir_path = ''
        # ファイル読取り方法(READ/LINE/OS)
        self.file_read_mode = "READ"
        # ファイル名が2バイト文字の場合にスキャン対象外とするか否か
        self.file_name_wchar = True

        # バイナリファイルをスキャン対象外とするか否か
        self.binary_reject = False
        # バイナリ判定を簡易的に行うか否か(binary_reject==True時)
        self.binary_simple_check = True
        # スキャン1(文字列の存在有無)の有効/無効
        self.scan1_enable = True
        # スキャン2にAND条件を適用
        self.scan2_mode_and = False
        # 出力内容(LINE/ALL/FILE/NONE)
        self.output_display = "LINE"
        # 出力結果のファイルパスを相対パスで表示するか否か
        self.output_file_path_rel = "ABS"
        # ログ出力(True/False)
        self.log_enable = "INFO"
        # 通知設定(NONE/MAIL/SLACK)
        self.notice_destination = "NONE"
        # メール通知設定 SMTPサーバー
        self.mail_smtp = "127.0.0.1"
        # メール通知設定 送信元アドレス
        self.mail_from_addr = ""
        # メール通知設定 通知先アドレス
        self.mail_to_addr = ""
        # メール通知設定 件名
        self.mail_subject = ""
        # OP25B環境で使用するポート
        self.mail_submission_port = 587
        # ログイン
        self.mail_login = ""
        # パスワード
        self.mail_passwd = ""

        self.__load_ignore()
        self.__load_config()

    def __load_ignore(self):
        u"""スキャン対象外ファイルの読み込み."""
        # ファイルの存在有無チェック
        if not os.path.exists(self.IGNORE_FILE_NAME):
            return None

        # スキャン対象外ファイルの読み込み
        key = ""
        white_list = []
        with open(self.IGNORE_FILE_NAME) as frh:
            for line in frh.readlines():
                line = line.strip()
                # 空行、コメント(#)以外は読み込み対象
                if len(line) > 0 and not line.startswith("#"):
                    # スキャン対象のディレクトリの記述
                    if line.startswith("["):
                        if len(key) > 0 and len(white_list) > 0:
                            self.IGNORE_FILE_LIST[key] = white_list
                        key = os.path.normpath(line[1:-1].strip())
                        white_list = []
                        continue
                    else:
                        if len(key) == 0:
                            # スキャン対象のディレクトリの記述がない中で、
                            # ファイルパスの記述されていた場合は無効とする
                            continue
                        # ホワイトリストにファイルパスを追加
                        white_list.append(line)

            # 未格納のホワイトリストを格納
            if len(key.strip()) > 0 and len(white_list) > 0:
                self.IGNORE_FILE_LIST[key] = white_list

    def __load_config(self):
        u"""設定ファイルの読み込み."""
        get_config = self.__CU.get_config

        # 設定ファイル
        my_path = os.path.dirname(os.path.abspath(__file__))
        my_name, ext = os.path.splitext(os.path.basename(__file__))
        ext = ".conf"
        conf_file = os.path.join(my_path, my_name + ext)

        # ファイルのチェック方法(READ/LINE/OS)
        config = [conf_file, "FILE_READ", "mode", "READ"]
        self.file_read_mode = get_config(*config)

        # ファイル名が2バイト文字の場合にスキャン対象外とするか否か
        config = [conf_file, "IGNORE", "file_name_wchar", True]
        self.file_name_wchar = get_config(*config)

        # スキャン対象外とする拡張子
        config = [conf_file, "IGNORE", "file_ext", "pdf,mo"]
        file_ext = get_config(*config)
        # ビリオドが付いてない場合は付加
        for ext in file_ext.split(","):
            if not ext.startswith("."):
                ext = "." + ext
            self.IGNORE_FILE_EXT.append(ext)

        # バイナリファイルはスキャン対象外とするか否か
        config = [conf_file, "BINARY", "binary_reject", False]
        self.binary_reject = get_config(*config)

        # バイナリファイル判定を簡易的に行うか否か
        config = [conf_file, "BINARY", "binary_simple_check", False]
        self.binary_simple_check = get_config(*config)

        # スキャンパターン1の有効/無効
        config = [conf_file, "SCAN", "scan1_enable", True]
        self.scan1_enable = get_config(*config)

        # スキャンパターン1で対象となる文字列
        config = [conf_file, "SCAN", "scan1_word", ""]
        scan1_word = get_config(*config)
        if len(scan1_word.strip()) > 0:
            self.SCAN1_WORD.extend(scan1_word.split(","))

        # スキャンパターン2の有効/無効
        config = [conf_file, "SCAN", "scan2_enable", True]
        self.scan2_enable = get_config(*config)

        # スキャンパターン2で対象となる文字列としきい値
        config = [conf_file, "SCAN", "scan2_word_dict", ""]
        word_dict = get_config(*config)
        if len(word_dict.strip()) > 0:
            self.SCAN2_WORD_DICT.update(literal_eval(word_dict))

        # スキャンパターン2にAND条件を適用する
        config = [conf_file, "SCAN", "scan2_mode_and", False]
        self.scan2_mode_and = get_config(*config)

        # 出力内容(LINE/ALL/FILE/NONE)
        config = [conf_file, "OUTPUT", "display", "LINE"]
        self.output_display = get_config(*config)

        # スキャン結果の出力内容から除外する
        config = [conf_file, "OUTPUT", "file_ext", "js"]
        file_ext = get_config(*config)
        # ビリオドが付いてない場合は付加
        for ext in file_ext.split(","):
            if not ext.startswith("."):
                ext = "." + ext
            self.OUTPUT_FILE_EXT.append(ext)

        # 出力結果のファイルパスを相対パスで表示するか否か
        config = [conf_file, "OUTPUT", "file_path_rel", "ABS"]
        self.output_file_path_rel = get_config(*config)

        # ログレベル
        config = [conf_file, "LOG", "enable", True]
        self.log_enable = get_config(*config)

        # 通知設定(NONE/MAIL/SLACK)
        config = [conf_file, "NOTICE", "destination", "NONE"]
        self.notice_destination = get_config(*config)

        # メール通知設定 SMTPサーバー
        config = [conf_file, "NOTICE", "mail_smtp", "127.0.0.1"]
        self.mail_smtp = get_config(*config)

        # メール通知設定 送信元アドレス
        config = [conf_file, "NOTICE", "mail_from_addr", ""]
        self.mail_from_addr = get_config(*config)

        # メール通知設定 通知先アドレス
        config = [conf_file, "NOTICE", "mail_to_addr", ""]
        self.mail_to_addr = get_config(*config)

        # メール通知設定 件名
        config = [conf_file, "NOTICE", "mail_subject", ""]
        self.mail_subject = get_config(*config)

        # OP25B環境で使用するポート
        config = [conf_file, "NOTICE", "mail_submission_port", 587]
        self.mail_submission_port = get_config(*config)

        # ログイン
        config = [conf_file, "NOTICE", "mail_login", ""]
        self.mail_login = get_config(*config)

        # パスワード
        config = [conf_file, "NOTICE", "mail_passwd", ""]
        self.mail_passwd = get_config(*config)

    def __printf(self, value=None):
        u"""このクラスの全ての出力を行うメソッド."""
        if self.log_enable:
            print value

    def scan_2_count_word(self, target_data):
        u"""特定の文字列の出現数をスキャンする.

        Args:
            target_data: 判定対象のデータ
        Returns:
            特定文字列ごとの出現数を辞書で返却
            Exsample:
                特定の文字列: ["AAA", "BBB"]のとき、
                AAAが0件、BBBが20件の場合
                return {"AAA":0, "BBB":20}
        """
        result_dict = {}
        for keyword in self.SCAN2_WORD_DICT.keys():
            result_dict[keyword] = target_data.count(keyword)
        return result_dict

    def scan_2_count_word_oscmd(self, target_file):
        u"""OSコマンドによる特定文字列の出現数をスキャン.

        Args:
            target_file: 判定対象のデータ
        Returns:
            特定文字列ごとの出現数を辞書で返却
            Exsample:
                特定の文字列: ["AAA", "BBB"]のとき、
                AAAが0件、BBBが20件の場合
                return {"AAA":0, "BBB":20}
        """
        result_dict = {}
        for keyword in self.SCAN2_WORD_DICT.keys():
            # コマンド生成
            cmd = 'grep -o "{}" {} | wc -l'.format(keyword, target_file)
            # 実行結果を取得
            res = subprocess.check_output(cmd, shell=True)
            # 出現数を保持
            result_dict[keyword] = int(res.strip())
        return result_dict

    def scan_1_find_word(self, target_data):
        u"""特定の文字列の有無をスキャンする.

        Args:
            target_data: 判定対象のデータ

        Returns:
            特定文字列ごとの有無を辞書で返却
            Exsample:
                特定の文字列: ["AAA", "BBB"]のとき、
                AAAが存在し、BBBが無い場合
                return {"AAA":True, "BBB":False}
        """
        result_dict = {}
        for word in self.SCAN1_WORD:
            result = False
            if target_data.find(word) >= 0:
                result = True
            result_dict[word] = result
        return result_dict

    def scan_1_find_word_oscmd(self, target_file):
        u"""OSコマンドによる特定文字列の有無をスキャン.

        Args:
            target_file

        Returns:
            特定文字列ごとの有無を辞書で返却
            Exsample:
                特定の文字列: ["AAA", "BBB"]のとき、
                AAAが存在し、BBBが無い場合
                return {"AAA":True, "BBB":False}
        """
        result_dict = {}
        for word in self.SCAN1_WORD:
            # コマンド生成
            cmd = 'grep -o "{}" {} | wc -l'.format(word, target_file)
            # 実行結果を取得
            res = subprocess.check_output(cmd, shell=True)
            # 判定
            result = False
            if res.strip() > 0:
                result = True
            result_dict[word] = result
        return result_dict

    def add_scan_result(self, file_path, scan1_result, scan2_result):
        u"""スキャン結果の格納.

        Args:
            file_path: 対象ファイル
            scan_target_data: スキャン対象データ
        """
        result = {}
        result["file_path"] = file_path

        # スキャン1(対象文字列の有無)の判定
        # どれか1つでもヒットした場合はTrue(怪しい)とする
        scan1_judge = False
        if True in scan1_result.values():
            scan1_judge = True
        result["result_scan_1_find_word_judge"] = scan1_judge
        result["detail_scan_1_find_word_result"] = scan1_result

        # スキャン2(対象文字列の出現数)の判定
        if self.scan2_mode_and:
            # AND条件の場合初期値:True
            scan2_judge = True
        else:
            # OR条件の場合初期値:False
            scan2_judge = False

        for keyword, count in scan2_result.items():
            border = self.SCAN2_WORD_DICT[keyword]
            if self.scan2_mode_and:
                # AND条件の場合
                if count < border:
                    # 一つでもしきい値を超えない場合はFalseとする
                    scan2_judge = False
                    break
            else:
                # OR条件の場合
                if count >= border:
                    # いずれかのしきい値を超えた場合はTrue(怪しい)とする
                    scan2_judge = True
                    break

        result["result_scan_2_count_word_judge"] = scan2_judge
        result["detail_scan_2_count_word_result"] = scan2_result

        # 最終的な判定結果
        if scan1_judge or scan2_judge:
            result["result"] = True
        else:
            result["result"] = False

        # 結果を格納
        self.RESULTS.append(result)

    def scan_files(self, file_path):
        u"""指定ファイルをスキャンする.

        Args:
            file_path: スキャン対象のファイルパス
        """
        # バイナリファイルは対象外とする場合(MIMEでチェック)
        if self.binary_reject:
            if not self.binary_simple_check:
                if self.__CU.is_binary(file_path):
                    return None

        # ファイルチェック方法
        # READ: ファイルを開き、一度に全て読み込みチェック
        if self.file_read_mode in ["READ"]:

            # ファイル読取り
            with open(file_path, "rU") as frh:
                if self.file_read_mode == "READ":
                    # 一度に全て読み込みチェック
                    scan_target_data = frh.read()
                    # self.scan_start(file_path, frh.read())

            # バイナリファイルは対象外とする場合(簡易チェック)
            if self.binary_reject:
                if self.binary_simple_check:
                    if self.__CU.is_binary_08h_char(scan_target_data):
                        return None

            # スキャン1 特定の文字列の有無
            scan1_result = self.scan_1_find_word(scan_target_data)

            # スキャン2 特定の文字列の出現数
            scan2_result = self.scan_2_count_word(scan_target_data)

        else:
            # OS: OSコマンドを用いる(grepコマンドが使えること)

            # スキャン1 特定の文字列の有無
            scan1_result = self.scan_1_find_word_oscmd(file_path)

            # スキャン2 特定の文字列の出現数
            scan2_result = self.scan_2_count_word_oscmd(file_path)

        # スキャン結果を格納
        self.add_scan_result(file_path, scan1_result, scan2_result)

    def get_results(self):
        u"""スキャン結果を整形して返却する.

        Returns:
            スキャン結果を整形したリスト
        """
        if self.output_display == "NONE":
            return None

        buffer_list = []
        # スキャン対象の出力
        buffer_list.append("Scan target: " + self.target_dir_path)

        for result in self.RESULTS:
            # 怪しいと判定したファイルが出力対象
            if result["result"]:

                file_path = result["file_path"]

                # 出力結果に表示しない拡張子
                ext = os.path.splitext(file_path)
                if ext[1] in self.OUTPUT_FILE_EXT:
                    continue

                # 怪しいと判定されたファイルのパスを相対パスで表示する
                if self.output_file_path_rel == "REL":
                    # スキャン対象ディレクトリから見た相対パス
                    file_path = os.path.relpath(
                        file_path, self.target_dir_path)

                    # パスの表記が「./」から始まるようにする
                    file_path = os.path.join("./", file_path)

                elif self.output_file_path_rel == "CUR":
                    # カレントディレクトリから見た相対パス
                    file_path = os.path.relpath(file_path)

                    # パスの表記が「./」から始まるようにする
                    # カレントディレクトリからみると上位(..)の場合は何もしない
                    if not file_path.startswith("."):
                        file_path = os.path.join("./", file_path)

                else:
                    # 結果は絶対パスで表示する
                    pass
                    # result["file_path"]には絶対パスで格納されているため、
                    # 特に処理は不要

                # 出力形式(LINE/ALL/FILE)
                if self.output_display == "LINE":
                    # ワンライナー
                    s1r = result["detail_scan_1_find_word_result"]
                    s2r = result["detail_scan_2_count_word_result"]
                    buf = "%s\t%s  \t%s" % (s1r, s2r, file_path)
                    buffer_list.append(buf)

                elif self.output_display == "ALL":
                    # 判定結果
                    buffer_list.append("result: %s" % (result["result"]))

                    # ファイルパス
                    buffer_list.append("file_path: %s" % (file_path))

                    # スキャンパターン1の結果
                    key = "result_scan_1_find_word_judge"
                    buffer_list.append("%s: %s" % (key, result[key]))
                    key = "detail_scan_1_find_word_result"
                    buffer_list.append("%s: %s" % (key, result[key]))

                    # スキャンパターン2の結果
                    key = "result_scan_2_count_word_judge"
                    buffer_list.append("%s: %s" % (key, result[key]))
                    key = "detail_scan_2_count_word_result"
                    buffer_list.append("%s: %s" % (key, result[key]))

                elif self.output_display == "FILE":
                    # ファイルパスのみ
                    buffer_list.append("file_path: %s" % (file_path))

        return buffer_list

    def print_results(self, buffer_list):
        u"""スキャン結果を出力する.

        Args:
            buffer_list: スキャン結果のリスト
        """
        # 結果内容
        buf = ""
        for line in buffer_list:
            buf = buf + line + os.linesep

        if not self.output_display == "NONE":
            # 結果の出力
            self.__printf(buf)

        # 通知
        if self.notice_destination == "NONE":
            return None
        elif self.notice_destination == "MAIL":
            # メールで通知
            obj = mail_util.MailUtil()
            # メール送信
            obj.send_op25b(
                self.mail_submission_port,
                self.mail_login,
                self.mail_passwd,
                self.mail_smtp,
                self.mail_from_addr,
                self.mail_to_addr,
                self.mail_subject,
                buf
            )
        elif self.notice_destination == "SLACK":
            # Slackに通知
            pass

    @staticmethod
    def __iterate_files(root_dir):
        u"""検索対象のディレクトリ配下にあるファイルを再帰的に列挙する.

        Args:
            root_dir: 検索対象のディレクトリパス
        Returns:
            検索対象のディレクトリ配下にあるファイルパス
        """
        for dir_path, dirs, files in os.walk(root_dir):
            yield dir_path
            for file_name in files:
                yield os.path.join(dir_path, file_name)

    def search_files(self, root_path="."):
        u"""指定ディレクトリ配下のファイルを検索する.

        Args:
            root_path: ファイル検索対象のディレクトリパス
                       default: current directory
        """
        # 相対パスの場合は絶対パスに変換しておく(末尾の/は除去)
        real_path = os.path.realpath(root_path)

        # スキャン対象外リストに指定ディレクトリの記載がある場合、パスを保持しておく
        white_list = []
        if real_path in self.IGNORE_FILE_LIST:
            for path in self.IGNORE_FILE_LIST[real_path]:
                ignore_path = os.path.normpath(os.path.join(real_path, path))
                white_list.append(ignore_path)

        # self.__printf(white_list)

        # 指定ディレクトリ配下のファイルを列挙
        for file_path in self.__iterate_files(real_path):
            # ディレクトリはスキャン対象外とする
            if not os.path.isfile(file_path):
                continue

            # ファイル名に2バイト文字が使われている場合はスキャン対象外とする
            if self.file_name_wchar and self.__CU.use_wchar(file_path):
                continue

            # スキャン対象外の拡張子
            ext = os.path.splitext(file_path)
            if ext[1] in self.IGNORE_FILE_EXT:
                continue

            # print file_path
            # スキャン対象外のファイルか判定
            is_ignore = False
            for ignore_path in white_list:
                if self.__CU.is_file_indir(file_path, ignore_path):
                    is_ignore = True
                    break

            # スキャン対象外
            if is_ignore:
                continue

            # ファイルをスキャンする
            self.scan_files(file_path)

    def print_help(self):
        u"""使用方法(ヘルプ)表示."""
        myname = __file__
        usage = """
        Usage:
            python %s <Scan Directory path>

        Exsample:
            python %s /home/hoge/
        """ % (myname, myname)
        self.__printf(usage)

    def start_with_param(self, argv):
        u"""スキャン開始.

        コマンドラインパラメータでスキャン対象ディレクトリのパスを指定する.
        Args:
            argv: コマンドラインパラメータ
                param1: スキャン対象のディレクトリパス
        """
        if len(argv) <= 1:
            self.print_help()
            return None

        if len(argv) > 1:
            # 出力結果格納用リスト
            output_list = []
            if os.path.exists(argv[1]):
                self.target_dir_path = argv[1]
                # スキャン開始時刻
                output_list.append(common_util.CommonUtil().get_nowtime())

                if os.path.isdir(argv[1]):
                    # 指定ディレクトリ配下のファイルを検索しスキャンする
                    self.search_files(argv[1])
                else:
                    # 指定ファイルをスキャンする
                    # ファイル指定時はスキャン対象外リストの効果は無し(記載してあってもスキャンする)
                    self.scan_files(argv[1])

                # スキャン結果を取得
                output_list.extend(self.get_results())
                output_list.append(common_util.CommonUtil().get_nowtime())

            else:
                output_list.append("not exists : " + argv[1])

            # 結果を表示
            self.print_results(output_list)


def main():
    u"""処理実行."""
    csf = CheckShadyFile()
    csf.start_with_param(sys.argv)

if __name__ == "__main__":
    main()
