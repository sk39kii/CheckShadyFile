# CheckShadyFile

怪しいファイルを検索します.

## Description

指定したディレクトリ配下に存在する怪しいファイルを検索し列挙します。  
ホワイトリストに記載されているファイルは対象外とします。

### 怪しいファイルって？

Webサイトの公開ディレクトリに、いつも間にか存在する身に覚えのないファイルのことです。  

* base64で難読化してある
* 16 進コード('\xhh')がやたら多い
* $GLOBALSがやたら多い
* 最後にevalに何かよくわからないデータを渡している

これらはもしかすると攻撃スクリプトかもしれません。  
他にも怪しいファイルが存在してないかチェックする場合に活用してください。  

## Requirement

- Python2.7

## Usage

```bash
Usage:
    python check_shady_file.py <Scan Directory path>

Exsample:
    python check_shady_file.py /var/www/html/hoge/
```

```bash
$ python check_shady_file.py /var/www/html/hoge/
2017-02-12_15:43:39.146
Scan target: /var/www/html/hoge/
{'eval': True}	{'$GLOBALS': 424, '64_decode': 0, '\\x': 104}  	/var/www/html/hoge/proxy01.php
{'eval': True}	{'$GLOBALS': 0, '64_decode': 1, '\\x': 0}  	/var/www/html/hoge/template03.php
{'eval': False}	{'$GLOBALS': 200, '64_decode': 0, '\\x': 0}  	/var/www/html/hoge/public/test.css
{'eval': True}	{'$GLOBALS': 0, '64_decode': 1, '\\x': 0}  	/var/www/html/hoge/public/utf00.php
2017-02-12_15:43:39.158
$ 
```

## Note
これを使ったとしても全て完全に探せる訳ではありません。  

CMSの設定管理が不十分だと外部から攻撃スクリプトをアップロードされている場合があります。  
怪しいファイルを発見したら、まずはCMSを最新にアップデートしましょう。  

またサーバーの設定が緩い可能性が高いので設定の見直しをおすすめします。


## Install


```
git clone https://github.com/sk39kii/CheckShadyFile.git
```

chardetのインストール
```
pip install chardet
```

## Licence
[MIT](https://github.com/sk39kii/CheckShadyFile/blob/master/LICENSE)
