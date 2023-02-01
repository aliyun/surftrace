# 前言

```
    小鹿在外面吃草的时候被狼跟踪，鹿妈妈赶紧学老虎叫吓跑了狼；在回家的路上，鹿妈妈语重心长的劝导小鹿：现在知道多掌握一门语言的重要性了吧！
```

&emsp;lua是一门奇怪的脚本开发语言，我之前开发工具的时候，是完全不考虑这种语言的。这门语言的吐槽点：

1. lua 数组的下标是从1开始的， 参考[说明](https://www.zhihu.com/question/19675689/answer/19174752)。用设计者原话说：it was thought to be most friendly for non-programmers，对非程序员友好，那基本上就是与程序员为敌了；
2. 语法有点繁琐：**function 要带上 end，if 要带上end， while/for 也要带上end，return的下一句一定要是end；几乎所有本地声明的变量都要带上local，不然很容易出现内存泄漏。** 乍一看一点都不优雅。
3. 资料匮乏。lua在它30多年的发展历程中从就从来没有火过，热度一直都跟 Fortran/COBOL/Lisp 等“冷门”语言混在同一阵营，导致它的相关资料和手册较少，感受度较低。

&emsp;当采用python 设计工具遇到性能瓶颈后，就迫切需要一种功能可替代的语言来实现。论性能，C是无与匹敌的，简短总结一下C的优势：

1. 几乎一切应用的基础，几乎是所有操作系统和编程语言的祖宗；
2. 贴近操作系统底层，几乎可以无所不能。

&emsp;但是论C语言的生态和开发进度就容易让人头疼，要开发严密性强的代码进度也着实令人着急。比如代码开发过程中涉及到内存申请，并要处理好每一个步骤的异常情况：

```C
static int beaver_threads_start(int thread, pthread_t ** tid_arr, struct beaver_message* pmsg) {
    int ret = 0;
    pthread_t *tids;

    tids = (pthread_t *) malloc(thread * sizeof (pthread_t));
    if (tids == NULL) {
        perror("beaver thread malloc.");
        ret = -ENOMEM;
        goto endMalloc;
    }
    for (int i = 0; i < thread; i ++) {
        tids[i] = 0;
    }
    *tid_arr = tids;

    ret = beaver_setup_message(pmsg);
    if (ret < 0) {
        goto endMessage;
    }

    for (int i = 0; i < thread; i ++) {
        ret = pthread_create(&tids[i], NULL, beaver_threads, pmsg);
        ASSERT_LOCKS(ret);
    }

    return ret;
    endMessage:
    free(tids);
    endMalloc:
    return ret;
}
```

&emsp;这种goto的设计过程写的着实让人难受，还很容易在goto里面释放资源的时候翻车，因此可以引出C 语言写应用的几个弱项。

## C语言不擅长的

1. 内存管理繁琐，容易用错，相信每位C开发者都深有体会，前面也有举例；
2. 哈希处理：我们在处理用户态数据的时候会频繁使用哈希数据，C可以引用 [uthash](http://troydhanson.github.io/uthash/index.html) 或者 [cJson](https://github.com/DaveGamble/cJSON) 等通用库，但是编码体验与python 等语言对比起来复杂度对比简直是天上地下；
3. 字符串处理：我们的探测工具可能要产生大量的字符串数据需要处理，而C本身并不擅长去生产或者加工字符串数据，类似python 中split/strip 等常规操作，用C去实现对开发的要求极高；
4. 不支持面向对象开发。面向对象设计具有易维护、易扩展、质量高、效率高等优势，参考[这里的总结和设计原则](https://www.cnblogs.com/sun_moon_earth/archive/2008/07/21/1247512.html)，适合大型项目使用。当然，软件质量是由开发者最终决定的，而不是采用什么开发方法。

&emsp;C++或许可以很好地克服以上不足点，而且可以全面兼容C。但是C++极度复杂，这门语言有太多的诱惑，程序员需要极度的自律才能驾驭住，就连Linus Torvalds 都对它恨之入骨。Rust/go或许更好，但感觉跟C互斥性很强，需要投入更多的学习成本和更多的学习时间，这样不可控因素就大了。能不能像小鹿学外语一样，是否可以从它的一门更亲近而且互通性很好的语言开始学，比如说都是偶蹄目的麋鹿语开始上手，反正都是鹿，障碍不会那么多，冷门一点也没关系，当掌握了麋鹿语以后，就可以很方便地同时与鹿、马、牛、驴进行交流了。

&emsp;小知识：

* 麋鹿外号四不像，鹿角、马头、牛蹄、驴尾
* C、C++、rust、go 等都是支持lua 扩展

## 为什么是lua

* 采用ANSI C 语言编写，依赖少，体积小，资源消耗较小
* 可以很容易嵌入到C、go、rust 应用中
* 有一个 luarocks 的生态圈，可以像python pip 一样安装三方库
* 自动内存管理
* 支持面向对象编程
* 支持数组、哈希、集合等特性
* 内置模式匹配，引入pystirng 库后可以像python 一样对字符串进行操作
* 支持词法闭包(closure)
* 支持协程
* luajit 可以加速执行速度，代码执行效率和C接近
* luajit ffi接口可以与so无缝对接
* ……

&emsp;总的来说，它在额外消耗有限的一小部分资源情况下，可以和C形成一个良好的互补，让C应用开发具备很多高级语言的特性。

&emsp;Lua并不是一门要你编写大量开发代码的语言，相反，Lua希望你仅用少量代码去解决关键性问题。

