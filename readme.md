# 課題解答内容

# 課題考察用

# 課題用 解答プロセス
課題の解答プロセスを記入する。

## 課題1 3000番ポートの削除
課題1の3000番ポートで来たものを削除するプログラムをL2monitor.pyで作成する。
2つのコマンドすクリムトを用意する。

片方では、
sudo python mn_topology.py

片方では、
sudo pyu-manager L2monitor.py

を実行する。

### プロセス1 フローエントリーをOFSに追加する
必要な要素は以下の通り
* Match条件
    * s2受信のポート番号
    * イーサタイプ
    * プロトコル番号
    * 宛先ポート番号
* action
    * パケット破棄

Match条件を先に記入した。
詳しくはプログラムを見ればわかるが、s2受信のポート番号の確認はlinksコマンドを用いて判断した。
UDPのプロトコル番号は17番。
宛先ポート番号は3000番。
イーサタイプは0x0080やったかな。

Actionのパケット破棄は、[]で終わり。

### プロセス2 破棄ができているか、プログラムの実行
上記の条件等を記入して、プログラムを実行すると、s2のサーバー側には何も表示されず、s1のクライアント側ではwarningが表示されたことから、プログラムは正しく実行している可能性が高い。

### プロセス3 WireSharkでの確認
後ほどWireSharkを用いて破棄が正しく行われているかを確認したい。

## 課題2 パケットロス率の定期的計測 
5秒ごとのパケットロス率の計算を行う。

### プロセス1 for文の中でどのような動作を行っているのかの確認
flow_statメッセージの内容が表示されている模様
一つのswitchからいくつかのメッセージがきていて、そのメッセージ全部がfor文を通ると抜けていく感じみたい。
それで、for文を抜けるとデバックを入れたので、動作がわかった。

### プロセス2 適当にポート番号を指定してパケット数の計算を行いたい
すでに作成されていた出力内容を考察して以下の通り、出力、入力の部分をみつけた。
* switch1のポート2からの出力
    * stat.instructions[0].actions[0].portが2
* switch2のポート3からの入力
    * stat.match["in_port"]が3

### プロセス3 ポート設定してパケットの数をカウント
パケットの数をカウントするようにした。
switch毎の届くとい特性から多少苦労した。
はじめはローカル変数で宣言をしていたため、メッセージが届くたびに片方が初期宣言に戻ってしまうことが原因。
したがって、グローバル宣言を行い、上記の課題の解決を計った。

### プロセス4 グローバル変数の宣言
グローバル変数を宣言することで、プロセス3における問題点を克服した。
4つのグローバル変数を用意した。
* s1_out_now
* s2_in_now
* s1_out_ago
* s2_in_ago

それぞれ、意味はプログラムの説明を参照
メッセージがきて、if文に入ると上記の"s1_out_now"と"s2_in_now"が更新される。

### プロセス5 ロス率の計算
プロセス4で更新された"s1_out_now"、"s2_in_now"を使用する。
どちらも更新されたら(片方ずつしか更新されないため)ロス率の計算を行う。
ロス率の計算を行ったらagoの方に現在のパケット数を入力し、次の計算にしようできるよに更新する。

### プロセス6 デバッグを標準出力に変更
ぐちゃぐちゃになっているものの、どんな流れで出力が行われているのかを確認したい。
だから、出力自体は残しておくために、標準ファイル出力にする。
→失敗なので行わない