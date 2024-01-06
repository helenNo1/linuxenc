#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h> // /usr/include/dirent.h
#include <string>
#include <iostream>
#include <vector>
#include <cstring>
#include <unistd.h>
#include <queue>
#include "foreach.h"
using namespace std;

// static vector<string> sufVecV = {".sh", ".7z", ".asm", ".aspx", ".avi", ".backup", ".bak", ".bmp", ".c", ".cfg", ".class", ".conf", ".config", ".cpp", ".cs", ".csproj", ".db", ".dbf", ".doc", ".docm", ".docx", ".gif", ".go", ".gz", ".h", ".hpp", ".htm", ".html", ".ini", ".java", ".jpeg", ".jpg", ".js", ".json", ".lua", ".mp4", ".pdf", ".png", ".ppt", ".pptm", ".pptx", ".properties", ".psd", ".py", ".rar", ".sln", ".sql", ".sqlite", ".svn-base", ".tar", ".txt", ".vbs", ".vcproj", ".vsd", ".vsdx", ".war", ".xls", ".xlsm", ".xlsx", ".xml", ".yaml", ".zip"};
const char *filePath = "/";

bool startsWith(const std::string &str, const std::string prefix)
{
    return (str.rfind(prefix, 0) == 0);
}

bool endsWith(const std::string &str, const std::string suffix)
{
    if (suffix.length() > str.length())
    {
        return false;
    }

    return (str.rfind(suffix) == (str.length() - suffix.length()));
}

bool endsWithVec(const std::string &str, std::vector<std::string> suffixVec)
{
    for (vector<string>::iterator it = suffixVec.begin(); it != suffixVec.end(); it++)
    {
        if (endsWith(str, *it))
        {
            return true;
        }
    }
    return false;
}


int getAbsoluteFilesBySuffix(string directory, queue<string> &filesAbsolutePath, string sufstr ) // 参数1[in]要变量的目录  参数2[out]存储文件名
{
    DIR *dir = opendir(directory.c_str()); // 打开目录   DIR-->类似目录句柄的东西
    if (dir == NULL)
    {
        cout << directory << " is not a directory or not exist!" << endl;
        return -1;
    }

    struct dirent *d_ent = NULL; // dirent-->会存储文件的各种属性
    char fullpath[128] = {0};
    char dot[3] = "."; // linux每个下面都有一个 .  和 ..  要把这两个都去掉
    char dotdot[6] = "..";

    while ((d_ent = readdir(dir)) != NULL) // 一行一行的读目录下的东西,这个东西的属性放到dirent的变量中
    {
        if ((strcmp(d_ent->d_name, dot) != 0) && (strcmp(d_ent->d_name, dotdot) != 0)) // 忽略 . 和 ..
        {
            if (d_ent->d_type == DT_DIR) // d_type可以看到当前的东西的类型,DT_DIR代表当前都到的是目录,在usr/include/dirent.h中定义的
            {

                string newDirectory = directory + string("/") + string(d_ent->d_name); // d_name中存储了子目录的名字
                                                                                       //       cout << "newDirectory: " << newDirectory << endl;
                if (directory[directory.length() - 1] == '/')
                {
                    newDirectory = directory + string(d_ent->d_name);
                }

                if (getAbsoluteFilesBySuffix(newDirectory, filesAbsolutePath, sufstr) == -1) // 递归子目录
                {
                    return -1;
                }
            }
            else // 如果不是目录
            {
                string absolutePath = directory + string("/") + string(d_ent->d_name); // 构建绝对路径
                // cout << "absolutePath: " << absolutePath << endl;
                if (directory[directory.length() - 1] == '/') // 如果传入的目录最后是/--> 例如a/b/  那么后面直接链接文件名
                {
                    absolutePath = directory + string(d_ent->d_name); // /a/b/1.txt
                }

                struct stat statbuf;
                stat(absolutePath.c_str(), &statbuf);
                // printf("size: %ld\n", statbuf.st_size);

                if (access(absolutePath.c_str(), W_OK) != -1)
                {
                    // printf("%s有可写权限\n", absolutePath.c_str());
                    if (endsWith(absolutePath, sufstr))
                    {
                        // cout << "file list push : " << absolutePath << endl;
                        filesAbsolutePath.push(absolutePath);
                    }
                }
                // cout << absolutePath << endl;
            }
        }
    }

    closedir(dir);
    return 0;
}