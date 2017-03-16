#ifndef __ERROR_CODE_H
#define __ERROR_CODE_H 1

/**
 * @brief 错误码定义
 *
 */
enum error_code {
    ERRCODE_NONE                =  0,   /**< 成功，无错误 */
    ERRCODE_UNKNOWN             = -1,   /**< 未知错误 */
    ERRCODE_SYSTEM              = -2,   /**< 系统错误 */
    ERRCODE_MEMORY              = -3,   /**< 内存不足 */
    ERRCODE_ARG                 = -4,   /**< 请求参数错误 */
    ERRCODE_PROTOCOL            = -5,   /**< 协议不支持 */
    ERRCODE_NOT_LOGIN           = -6    /**< 未登陆 */
    

};

#endif
