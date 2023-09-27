#include <iostream>
#include <queue>

using namespace std;

int getAbsoluteFiles(string directory, queue<string> &filesAbsolutePath);
int getAbsoluteFilesBySuffix(string directory, queue<string> &filesAbsolutePath);