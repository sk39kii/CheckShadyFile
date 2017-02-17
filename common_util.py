# -*- coding: utf-8 -*-

u"""汎用メソッドを集めたユーティリティ."""

__version__ = '0.3.0'
__date__ = '2017/02/8'

import chardet
import ConfigParser
from datetime import datetime

import mimetypes
import os.path


class CommonUtil(object):
    u"""汎用ユーティリティクラス.

    * extract_strings: 文字列から特定の文字列を抽出
    * is_binary: バイナリファイル判定
    * is_binary_08h_char: バイナリコードの有無を判定
    * read_dump: ファイルの中身を全て文字データとして取得する
    * is_relpath: パスが相対パスか否かを判定する
    * is_windows: 実行しているマシンのOSがWindowsか否か判断する
    * get_config_key_value: 設定ファイルから指定されたキーの値を取得する
    * get_config: 設定ファイルやセクションキーが存在しない場合はデフォルト値を返却する
    * if_none_set: 値のNoneチェックと型変換を行う
    * get_nowtime: 現在日時の取得する
    * use_wchar: 値に2バイト文字が含まれているか判定する
    """

    # 自クラスのインスタンス
    _instance = None

    @classmethod
    def __new__(cls, *args, **kwargs):
        u"""自クラスのインスタンス生成."""
        if cls._instance is None:
            cls._instance = object.__new__(cls)
        return cls._instance

    def __init__(self):
        u"""__init__ メソッド.

        ※__new__が先に呼ばれる
        """
        pass

    @classmethod
    def extract_strings(cls, src, from_str, to_str=None):
        u"""文字列から特定の文字列を抽出する.

        Args:
            src: 抽出元の文字列
            from_str: 抽出目的である文字列の直前文字列
            to_str: 抽出目的である文字列の直後文字列

        Returns:
            抽出目的の文字列を返却
            Example:
                src = "AAABBBCCCDDDEEE"
                例1: 直後文字列の指定あり
                    scraping_from_str(src, 'BBB', 'DDD')
                    # CCC
                例2: 直後文字列の指定なしの場合、末尾までを返却
                    scraping_from_str(src, 'BBB')
                    # CCCDDDEEE
                例3: 直後文字列が指定あり(だが存在しない)場合、末尾までを返却
                    scraping_from_str(src, 'BBB', 'ZZZ')
                    # CCCDDDEEE
                例4: 直前文字列が存在しない場合は、空文字を返却
                    scraping_from_str(src, 'ZZZ')
                    # ''
        """
        if src.find(from_str) > -1:
            start_idx = src.find(from_str) + len(from_str)
            if to_str is None:
                # 例2: 直後文字列の指定なしの場合、末尾までを返却
                return src[start_idx:]
            else:
                if src.find(to_str) > -1:
                    # 直後文字列は、直前文字列の出現位置以降を対象とする
                    end_idx = src.find(to_str, start_idx)
                    # 例1: 直後文字列の指定あり
                    return src[start_idx:end_idx]
                else:
                    # 例3: 直後文字列が指定あり(だが存在しない)場合、末尾までを返却
                    return src[start_idx:]
        else:
            # 例4: 直前文字列が存在しない場合は、空文字を返却
            return ''

    def is_binary(self, target, ascii_code_check=None):
        u"""バイナリファイル判定.

        MIMEタイプで判別、MIMEで判別不能な時はデータで判別する.
        MIME不明時はファイルの中身のエンコードで判断する(エンコード不明時はバイナリとする)

        Args:
            target: 判定対象のファイル
            ascii_code_check: アスキーコードチェック(デフォルト:None=チェックしない)

        Returns:
            True: Binary    False: Not Binary
        """
        ret = False
        mime = mimetypes.guess_type(target)[0]
        if mime is None:
            # MIMEで判別不能の場合(拡張子なしなど?)
            # ret = True

            # ファイルの中身で判断(chardetのエンコードで判断)
            buf = self.read_dump(target, 'rb')
            encode = chardet.detect(buf)['encoding']

            # エンコード不明時はバイナリとする
            if encode is None:
                ret = True

            # アスキコードチェック
            if ascii_code_check:
                # アスキーコードの08H以下(制御文字)の文字がある場合はバイナリ
                if self.is_binary_08h_char(buf):
                    ret = True

        elif mime.find('office') > -1:
            ret = True
        elif mime.startswith('image'):
            ret = True
        elif mime.startswith('text'):
            ret = False
        elif mime.startswith('application/vnd.ms-excel'):
            # CSV is not binary
            ret = False
        elif mime.find('byte-compiled'):
            ret = True
        return ret

    @staticmethod
    def is_binary_08h_char(buf):
        u"""バイナリコードの有無を判定する.

        データにASCIIコードの08H以下のコードの有無で判別する。

        Args:
            buf: チェック対象のデータ

        Returns:
            True: Binary    False: Not Binary
        """
        ret = False
        ord_cd = map(ord, list(buf))
        for num in range(0, 9):
            if num in ord_cd:
                ret = True
                break
        return ret

    @staticmethod
    def read_dump(dump_path, mode='r'):
        u"""ファイルの中身を全て文字データとして取得する.

        Args:
            dump_path: 読み込み対象ファイルパス
            mode: 読み取りモード(デフォルト:r=読み取り)

        Returns:
            ファイルデータ
        """
        buf = ''
        with open(dump_path, mode) as fhdl:
            buf = fhdl.read()
        return buf

    @staticmethod
    def is_relpath(target_path):
        u"""パスが相対パスか否かを判定する.

        Args:
            target_path: 判定対象のパス

        Returns:
            True: 相対パス  False: 相対パスではない
        """
        if target_path is None:
            return False

        if os.path.isabs(target_path):
            return False
        else:
            return True

    @staticmethod
    def is_file_indir(file_path, dir_path):
        u"""指定されたファイルパスが特定のディレクトリパス配下か判定する.

        Args:
            file_path: ファイルパス
            dir_path: ディレクトリパス

        Returns:
            True: ファイルがディレクトリ配下のパス, False:ディレクトリ配下でない

            Exsample1:
                file_path = '/var/www/html/target/index.html'
                dir_path = '/var/www/html/target'
                return True
            Exsample2:
                同じファイルパスでもTrueを返却する
                file_path = '/var/www/html/target/index.html'
                dir_path = '/var/www/html/target/index.html'
                return True
        """
        file_path = os.path.normpath(file_path)
        dir_path = os.path.normpath(dir_path)

        if file_path.find(dir_path) > -1:
            return True
        else:
            return False

    @staticmethod
    def is_windows():
        u"""実行しているマシンのOSがWindowsか否か判断する."""
        if os.name == "posix":
            return False
        else:
            return True

    @staticmethod
    def get_config_key_value(config_file, section, key):
        u"""設定ファイルから指定されたキーの値を取得する.

        設定ファイルやセクションキーが存在しない場合はNoneを返却する

        Args:
            config_file: 設定ファイルのパス
            section: 取得対象のセクション
            key: 取得対象のキー

        Returns:
            指定したキーの値
        """
        try:
            ini = ConfigParser.SafeConfigParser()
            ini.read(config_file)
            return ini.get(section, key)
        except ConfigParser.Error:
            # print(error.message)
            return None

    def get_config(self, config_file, section, key, default):
        u"""設定ファイルから指定キーの値を取得する.

        設定ファイルやセクションキーが存在しない場合はデフォルト値を返却する

        Args:
            config_file: 設定ファイルのパス
            section: 取得対象のセクション
            key: 取得対象のキー
            default: デフォルト値

        Returns:
            指定したキーの値
        """
        value = default
        config_value = self.get_config_key_value(config_file, section, key)
        if config_value is not None and len(config_value.strip()) == 0:
            config_value = None
        value = self.if_none_set(config_value, default)
        return value

    @staticmethod
    def if_none_set(value, default):
        u"""値のNoneチェックと型変換を行う.

        valueがNoneの場合にdefaultを返却する、Noneでない場合はvalueを返却.
        返却時にdefaultと同じ型で返却する

        Args:
            value: Noneチェック対象
            default: valueがNoneの場合に返却する値

        Returns:
            valueがNoneの場合: default、valueがNoneでない場合: value
        """
        ret = None
        if value is None:
            ret = default
        else:
            if isinstance(default, bool) and (not isinstance(value, bool)):
                if value.lower() == "false":
                    ret = False
                else:
                    ret = True
            elif isinstance(default, str) and (not isinstance(value, str)):
                ret = str(value)
            elif isinstance(default, int) and (not isinstance(value, int)):
                ret = int(value)
            elif isinstance(default, float) and (not isinstance(value, float)):
                ret = float(value)
            else:
                ret = value
        return ret

    def get_nowtime(self):
        u"""現在日時の取得する."""
        now = datetime.today()
        msec = now.microsecond // 1000
        return now.strftime(u'%Y-%m-%d_%H:%M:%S') + '.%03d' % (msec)

    def use_wchar(self, value):
        u"""値に2バイト文字が含まれているか判定する.

        Args:
            value: チェック対象の値

        Returns:
            True: 2バイト文字が含まれている、False: 含まれてない
        """
        encode = "utf-8"
        if self.is_windows():
            encode = "cp932"
        ret = False
        try:
            if isinstance(value, str):
                value = unicode(value, encode)

            for char in value:
                if ord(char) > 255:
                    ret = True
        except UnicodeDecodeError:
            print value
            # print ude.message
        return ret


def main():
    u"""処理呼び出し."""
    pass


if __name__ == '__main__':
    main()
