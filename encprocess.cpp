//https://zhuanlan.zhihu.com/p/558285964
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <fstream>
#include <sstream>
#include <iostream>
#include <vector>
#include <fstream>
#include <unistd.h>
#include <pthread.h>
#include <semaphore.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>
#include <queue>
#include "foreach.h"
#include "foreach.cpp"
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <errno.h>

using namespace std;

#define KEY_LENGTH 2048           // 密钥长度
#define PUB_KEY_FILE "pubkey.pem" // 公钥路径
#define PRI_KEY_FILE "prikey.pem" // 私钥路径
#define thread_num 10

pthread_mutex_t mutex_x = PTHREAD_MUTEX_INITIALIZER;
queue<string> wok_file_list;
int padding = RSA_PKCS1_PADDING;
string pub_key;
string pri_key;
string sufstr;
typedef void *(*ThreadFunc)(void *);
ThreadFunc tf = NULL;

// 从文件读入到string里
string readFileIntoString(const string filename)
{
    ifstream ifile(filename);
    // 将文件读入到ostringstream对象buf中
    ostringstream buf;
    char ch;
    while (buf && ifile.get(ch))
    {
        buf.put(ch);
    }

    // 返回与流对象buf关联的字符串
    return buf.str();
}

bool exists_test0(const string &name)
{
    if (FILE *file = fopen(name.c_str(), "r"))
    {
        fclose(file);
        return true;
    }
    else
    {
        return false;
    }
}

/*
制造密钥对：私钥和公钥
**/
void GenerateRSAKey(string &out_pub_key, string &out_pri_key)
{

    if (exists_test0(PRI_KEY_FILE) && exists_test0(PUB_KEY_FILE))
    {
        out_pub_key = readFileIntoString(PUB_KEY_FILE);
        out_pri_key = readFileIntoString(PRI_KEY_FILE);
        return;
    }

    size_t pri_len = 0;      // 私钥长度
    size_t pub_len = 0;      // 公钥长度
    char *pri_key = nullptr; // 私钥
    char *pub_key = nullptr; // 公钥

    // 生成密钥对
    RSA *keypair = RSA_generate_key(KEY_LENGTH, RSA_3, NULL, NULL);

    BIO *pri = BIO_new(BIO_s_mem());
    BIO *pub = BIO_new(BIO_s_mem());

    // 生成私钥
    PEM_write_bio_RSAPrivateKey(pri, keypair, NULL, NULL, 0, NULL, NULL);
    // 注意------生成第1种格式的公钥
    // PEM_write_bio_RSAPublicKey(pub, keypair);
    // 注意------生成第2种格式的公钥（此处代码中使用这种）
    PEM_write_bio_RSA_PUBKEY(pub, keypair);

    // 获取长度
    pri_len = BIO_pending(pri);
    pub_len = BIO_pending(pub);

    // 密钥对读取到字符串
    pri_key = (char *)malloc(pri_len + 1);
    pub_key = (char *)malloc(pub_len + 1);

    BIO_read(pri, pri_key, pri_len);
    BIO_read(pub, pub_key, pub_len);

    pri_key[pri_len] = '\0';
    pub_key[pub_len] = '\0';

    out_pub_key = pub_key;
    out_pri_key = pri_key;

    // 将公钥写入文件
    ofstream pub_file(PUB_KEY_FILE, ios::out);
    if (!pub_file.is_open())
    {
        perror("pub key file open fail:");
        return;
    }
    pub_file << pub_key;
    pub_file.close();

    // 将私钥写入文件
    ofstream pri_file(PRI_KEY_FILE, ios::out);
    if (!pri_file.is_open())
    {
        perror("pri key file open fail:");
        return;
    }
    pri_file << pri_key;
    pri_file.close();

    // 释放内存
    RSA_free(keypair);
    BIO_free_all(pub);
    BIO_free_all(pri);

    free(pri_key);
    free(pub_key);
}

/*
@brief : 公钥加密
@para  : clear_text  -[i] 需要进行加密的明文
         pri_key     -[i] 私钥
@return: 加密后的数据
**/
string RsaPubEncrypt(const string &clear_text, const string &pub_key)
{
    string encrypt_text;
    BIO *keybio = BIO_new_mem_buf((unsigned char *)pub_key.c_str(), -1);
    RSA *rsa = RSA_new();
    // 注意-----第1种格式的公钥
    // rsa = PEM_read_bio_RSAPublicKey(keybio, &rsa, NULL, NULL);
    // 注意-----第2种格式的公钥（这里以第二种格式为例）
    rsa = PEM_read_bio_RSA_PUBKEY(keybio, &rsa, NULL, NULL);
    if (rsa == nullptr)
    {
        BIO_free_all(keybio);
        return "";
    }

    // 获取RSA单次可以处理的数据块的最大长度
    int key_len = RSA_size(rsa);
    int block_len = key_len - 11; // 因为填充方式为RSA_PKCS1_PADDING, 所以要在key_len基础上减去11

    // 申请内存：存贮加密后的密文数据
    char *sub_text = new char[key_len + 1];
    memset(sub_text, 0, key_len + 1);
    int ret = 0;
    int pos = 0;
    string sub_str;
    // 对数据进行分段加密（返回值是加密后数据的长度）
    while (pos < clear_text.length())
    {
        sub_str = clear_text.substr(pos, block_len);
        memset(sub_text, 0, key_len + 1);
        ret = RSA_public_encrypt(sub_str.length(), (const unsigned char *)sub_str.c_str(), (unsigned char *)sub_text, rsa, RSA_PKCS1_PADDING);
        if (ret >= 0)
        {
            encrypt_text.append(string(sub_text, ret));
        }
        pos += block_len;
    }

    // 释放内存
    BIO_free_all(keybio);
    RSA_free(rsa);

    delete[] sub_text;

    return encrypt_text;
}

/*
@brief : 私钥解密
@para  : cipher_text -[i] 加密的密文
         pub_key     -[i] 公钥
@return: 解密后的数据
**/
string RsaPriDecrypt(const string &cipher_text, const string &pri_key)
{
    string decrypt_text;
    RSA *rsa = RSA_new();
    BIO *keybio;
    keybio = BIO_new_mem_buf((unsigned char *)pri_key.c_str(), -1);

    rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa, NULL, NULL);
    if (rsa == nullptr)
    {
        unsigned long err = ERR_get_error(); // 获取错误号
        char err_msg[1024] = {0};
        ERR_error_string(err, err_msg); // 格式：error:errId:库:函数:原因
        printf("err msg: err:%ld, msg:%s\n", err, err_msg);
        return string();
    }

    // 获取RSA单次处理的最大长度
    int key_len = RSA_size(rsa);
    char *sub_text = new char[key_len + 1];
    memset(sub_text, 0, key_len + 1);
    int ret = 0;
    string sub_str;
    int pos = 0;
    // 对密文进行分段解密
    while (pos < cipher_text.length())
    {
        sub_str = cipher_text.substr(pos, key_len);
        memset(sub_text, 0, key_len + 1);
        ret = RSA_private_decrypt(sub_str.length(), (const unsigned char *)sub_str.c_str(), (unsigned char *)sub_text, rsa, RSA_PKCS1_PADDING);
        if (ret >= 0)
        {
            decrypt_text.append(string(sub_text, ret));
            printf("pos:%d, sub: %s\n", pos, sub_text);
            pos += key_len;
        }
    }
    // 释放内存
    delete[] sub_text;
    BIO_free_all(keybio);
    RSA_free(rsa);

    return decrypt_text;
}

bool isFileExists_ifstream(string &name)
{
    ifstream f(name.c_str());
    return f.good();
}

void *decOne(void *arg)
{
    string filename;
    string noenc_filename;

    while (1)
    {
        pthread_mutex_lock(&mutex_x);
        if (wok_file_list.empty())
            break;
        filename = wok_file_list.front();
        wok_file_list.pop();
        pthread_mutex_unlock(&mutex_x);

        noenc_filename = filename.substr(0, filename.size() - 4);
        if (isFileExists_ifstream(noenc_filename))
        {
            return NULL;
        }

        try
        {
            string src_text;
            string decrypt_text;

            src_text = readFileIntoString(filename);
            remove(filename.c_str());
            decrypt_text = RsaPriDecrypt(src_text, pri_key);
            ofstream outfile;
            outfile.open(noenc_filename);
            outfile << decrypt_text;
            outfile.close();
            cout << "succ dec: " << filename << endl;
        }
        catch (...)
        {
            cout << "fail dec: " << filename << endl;
        }
    }

    return NULL;
}

void encOneProcess(string filename)
{
    string enc_filename;

    while (1)
    {

        enc_filename = filename + ".enc";
        if (isFileExists_ifstream(enc_filename))
        {
            return ;
        }

        try
        {
            string src_text;
            string encrypt_text;

            src_text = readFileIntoString(filename);
            cout << "333: " << endl;
            //           cout << src_text << endl;
            remove(filename.c_str());
            encrypt_text = RsaPubEncrypt(src_text, pub_key);
            ofstream outfile;
            string enc_filename = filename + ".enc";
            outfile.open(enc_filename);
            outfile << encrypt_text;
            outfile.close();
            cout << "succ: " << filename << endl;
        }
        catch (...)
        {
            cout << "fail: " << filename << endl;
        }
        cout << 346 << endl;
    }

    return ;
}

void *encOne(void *arg)
{
    string filename;
    string enc_filename;

    while (1)
    {

        pthread_mutex_lock(&mutex_x);
        if (wok_file_list.empty())
            break;
        cout << "313 size " << wok_file_list.size() << endl;
        filename = wok_file_list.front();
        cout << "315 filename " << filename << endl;
        wok_file_list.pop();
        cout << "317 size " << wok_file_list.size() << endl;
        pthread_mutex_unlock(&mutex_x);

        enc_filename = filename + ".enc";
        if (isFileExists_ifstream(enc_filename))
        {
            return NULL;
        }

        try
        {
            string src_text;
            string encrypt_text;

            src_text = readFileIntoString(filename);
            cout << "333: " << endl;
            //           cout << src_text << endl;
            remove(filename.c_str());
            encrypt_text = RsaPubEncrypt(src_text, pub_key);
            ofstream outfile;
            string enc_filename = filename + ".enc";
            outfile.open(enc_filename);
            outfile << encrypt_text;
            outfile.close();
            cout << "succ: " << filename << endl;
        }
        catch (...)
        {
            cout << "fail: " << filename << endl;
        }
        cout << 346 << endl;
    }

    return NULL;
}

int main(int argc, char *argv[])
{

    if (argc < 3)
    {
        cout << "argc < 3" << endl;
        exit(0);
    }

    if (strcmp(argv[1], "enc") == 0)
    {
        sufstr = ".txt";
        tf = encOne;
    }
    else if (strcmp(argv[1], "dec") == 0)
    {
        sufstr = ".enc";
        tf = decOne;
    }
    else
    {
        cout << "argv[1] err " << endl;
        exit(1);
    }

    GenerateRSAKey(pub_key, pri_key);
    if (pub_key.size() == 0 || pri_key.size() == 0)
    {
        cout << "key err" << endl;
        exit(0);
    }

    /*
    cout <<"pubkey: " << endl;
    cout << pub_key << endl;
    cout <<"prikey: " << endl;
    cout << pri_key << endl;
    // exit(0);
*/

    getAbsoluteFilesBySuffix(argv[2], wok_file_list, sufstr);
    cout << "file list size:\t" << wok_file_list.size() << endl;
    // exit(0);

    int fd[2];
    int ret;
    pid_t pid;
    // 创建一个管道
    ret = pipe(fd);
    if (ret < 0)
    {
        perror("pipe error");
        return -1;
    }
    int i = 0;
    int n = 2;
    for (i = 0; i < n; i++)
    {
        // 创建子进程
        pid = fork();
        if (pid < 0)
        {
            perror("fork error");
            return -1;
        }
        else if (pid == 0)
        {
            break;
        }
    }
    // if (i == n)
    if (i == n)
    {

        // 父进程中关闭管道，只做子进程回收
        close(fd[0]);
        close(fd[1]);
        pid_t wpid;
        int status;
        while (1)
        {
            // 等待回收子进程
            wpid = waitpid(-1, &status, WNOHANG); // 不阻塞地回收所有进程
            if (wpid == 0)                        // 没有子进程退出
            {
                sleep(1); // 可加可不加，避免大量重复循环
                continue;
            }
            else if (wpid == -1) // 已经没有子进程
            {
                printf("no child is living, wpid==[%d]\n", wpid);
                exit(0);
            }
            else if (wpid > 0)
            {
                if (WIFEXITED(status)) // 正常退出
                {
                    printf("child normal exited, status==[%d]\n", WEXITSTATUS(status));
                }
                else if (WIFSIGNALED(status)) // 被信号杀死
                {
                    printf("child killed by signo==[%d]\n", WTERMSIG(status));
                }
            }
        }
    }
    // 第一个子进程
    if (i == 0)
    {
        printf("write child: fpid==[%d], cpid==[%d]\n", getppid(), getpid());
        close(fd[0]);
        while (!wok_file_list.empty())
        {
            string srcfilename = wok_file_list.front();
            wok_file_list.pop();
            char buf[256] = {0};
            memset(buf, 0, sizeof(buf));
            strcpy(buf, srcfilename.c_str());
            // char huanhang[] = {'\n'};
            // strcat(buf, huanhang);
            write(fd[1], buf, sizeof(buf));
        }

        // 将标准输出重定向到管道到写端
        // dup2(fd[1], STDOUT_FILENO);
        // execlp("ps", "ps", "aux", NULL);
        // perror("execlp error");

        // close(fd[1]);
    }
    // 第2个子进程以后的进程
    if (i > 0 && i < n)
    {
        printf("read child: fpid==[%d], cpid==[%d]\n", getppid(), getpid());
        close(fd[1]);
        char buf[256] = {0};
        while (1)
        {
            memset(buf, 0, sizeof(buf));
            int ret = read(fd[0], buf, sizeof(buf));
            if (ret == 0)
            {
                printf("read over \n");
                break;
            }
            else if (ret > 0)
            {
                string oldbuf = buf;
                char huanhang[] = {'\n'};
                strcat(buf, huanhang);
                write(STDOUT_FILENO, buf, ret);
                encOneProcess(oldbuf);
            }
        }
    }

    // pthread_t thread_list[thread_num];
    // int i, j, iRet;
    // for (i = 0; i < thread_num; i++)
    // {
    //     iRet = pthread_create(
    //         &thread_list[i],
    //         NULL,
    //         tf,
    //         NULL);

    //     if (iRet)
    //     {
    //         perror("pthread create");
    //         return iRet;
    //     }
    // }

    // for (j = 0; j < thread_num; j++)
    // {
    //     pthread_join(thread_list[j],
    //                  NULL);
    // }

    return 0;
}