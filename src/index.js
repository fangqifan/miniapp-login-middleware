import clone from "just-clone";
import extend from "just-extend";
import { LoginModule, LoginStatusEnum } from 'miniapp-token-based-login'
import { Middleware } from 'request-middleware-pipeline';
import WechatContextNames from 'miniapp-middleware-contracts';


const defaultOptions = {
    attachRequestOptions: (requstOptions, loginToken) => {
        if (loginToken) {
            requstOptions.header = requstOptions.header || {};
            requstOptions.header['Authorization'] = 'Bearer ' + loginToken;
        }
    },
    maxRetryCount: 3
};

const privateNames = {
    loginModule: Symbol('loginModule'),
    options: Symbol('options'),
    retryCount: Symbol('retryCount'),
};

function recoveryContextData(contextData, newData) {
    let keys = Object.keys(contextData);
    keys.forEach(key => {
        delete contextData[key];
    })
    extend(true, contextData, newData);
}

export default class WechatLoginMiddleware extends Middleware {
    constructor(nextMiddleware, options) {
        super(nextMiddleware);

        this[privateNames.options] = extend(true, {}, defaultOptions, options);
        this[privateNames.loginModule] = this[privateNames.options].loginModule || new LoginModule();
        this[privateNames.retryCount] = 0;
    }

    async invoke(middlewareContext) {
        //缓存context data 用于登录重试
        let cacheData = clone(middlewareContext.data);
        // 读取本地login token 附加在request上
        const requestOptions = middlewareContext.data[WechatContextNames.WxRequestOptions] = middlewareContext.data[WechatContextNames.WxRequestOptions] || {};
        const loginToken = this[privateNames.loginModule].loginToken;

        this[privateNames.options].attachRequestOptions(requestOptions, loginToken);

        await this.next(middlewareContext);

        const response = middlewareContext.data[WechatContextNames.WxResponse] = middlewareContext.data[WechatContextNames.WxResponse] || {};
        if (response.statusCode === 401) {
            let currentLoginStatus = this[privateNames.loginModule].status;
            //登陆失败的将不再尝试登陆
            if (currentLoginStatus.status === LoginStatusEnum.LoggedInFailed) {
                return;
            }
            if (currentLoginStatus.status === LoginStatusEnum.LoggedIn) {
                currentLoginStatus.changeStatus(LoginStatusEnum.NotLoggedIn);
            }
            await this[privateNames.loginModule].login();
            //如果登录成功 则重置context data并重试
            if (currentLoginStatus.status === LoginStatusEnum.LoggedIn) {
                if (this[privateNames.options].maxRetryCount > ++this[privateNames.retryCount]) {
                    currentLoginStatus.changeStatus(LoginStatusEnum.NotLoggedIn);
                    return;
                }
                recoveryContextData(middlewareContext.data, cacheData);
                await this.invoke(middlewareContext);
            }
        }
    }

    config(options) {
        this[privateNames.options] = extend(true, this[privateNames.options], options);
    }
}