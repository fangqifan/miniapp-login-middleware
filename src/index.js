import clone from "just-clone";
import extend from "just-extend";
import { LoginModule, LoginStatusEnum } from 'miniapp-token-based-login'
import { Middleware } from 'request-middleware-pipeline';
import Contracts from 'miniapp-middleware-contracts';

const defaultOptions = {
    attachRequestOptions: (requstOptions, loginToken) => {
        if (loginToken) {
            requstOptions.header = requstOptions.header || {};
            requstOptions.header['Authorization'] = 'Bearer ' + loginToken;
        }
    },
    maxRetryCount: 3,
    loginModule: new LoginModule()
};

const privateNames = {
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

export default class extends Middleware {
    constructor(nextMiddleware, options) {
        super(nextMiddleware);

        this[privateNames.options] = extend({}, defaultOptions, options);
        this[privateNames.retryCount] = 0;
    }

    async invoke(middlewareContext) {
        //缓存context data 用于登录重试
        let cacheData = clone(middlewareContext.data);
        // 读取本地login token 附加在request上
        const requestOptions = middlewareContext.data[Contracts.WxRequestOptions] = middlewareContext.data[Contracts.WxRequestOptions] || {};
        const loginToken = this[privateNames.options].loginModule.loginToken;

        this[privateNames.options].attachRequestOptions(requestOptions, loginToken);

        await this.next(middlewareContext);

        const response = middlewareContext.data[Contracts.WxResponse] = middlewareContext.data[Contracts.WxResponse] || {};
        if (response.statusCode === 401) {
            let currentLoginStatus = this[privateNames.options].loginModule.status;
            //登陆失败的将不再尝试登陆
            if (currentLoginStatus.status === LoginStatusEnum.LoggedInFailed) {
                return;
            }
            if (currentLoginStatus.status === LoginStatusEnum.LoggedIn) {
                currentLoginStatus.changeStatus(LoginStatusEnum.NotLoggedIn);
            }
            await this[privateNames.options].loginModule.login();
            //如果登录成功 则重置context data并重试
            if (currentLoginStatus.status === LoginStatusEnum.LoggedIn) {
                if (this[privateNames.retryCount] > this[privateNames.options].maxRetryCount) {
                    currentLoginStatus.changeStatus(LoginStatusEnum.LoggedInFailed);
                    return;
                }
                this[privateNames.retryCount]++;
                recoveryContextData(middlewareContext.data, cacheData);
                await this.invoke(middlewareContext);
            }
        }
    }

    config(options) {
        this[privateNames.options] = extend(this[privateNames.options], options);
    }
}