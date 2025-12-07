#include <stdint.h>
#include <stddef.h>
#include "mxml.h"

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size){
    if(Size == 0) return 0;
    char buf[Size+1];
    for(size_t i=0;i<Size;i++){
        buf[i]=(char)Data[i];
    }
    buf[Size]='\0';
    mxml_options_t *options = mxmlOptionsNew();
    if(!options) return 0;
    mxml_node_t *root = mxmlLoadString(NULL, options, buf);
    if(root) mxmlDelete(root);
    mxmlOptionsDelete(options);
    return 0;
}