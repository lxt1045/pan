package auth

import (
	"bytes"
	"encoding/json"
	"fmt"
	"image/png"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/iikira/BaiduPCS-Go/requester"
	"github.com/jsyzchen/pan/conf"
	"github.com/jsyzchen/pan/utils/httpclient"
	"github.com/peterh/liner"
	baidulogin "github.com/qjfoidnh/Baidu-Login"
)

var raw = `
GET /oauth/2.0/authorize?client_id=kB968i7bDCqXhAS7RDWAvpFWevvWAGBK&redirect_uri=oob&response_type=token&scope=basic%2Cnetdisk HTTP/1.1
Host: openapi.baidu.com
Connection: keep-alive
sec-ch-ua: "Chromium";v="88", "Google Chrome";v="88", ";Not A Brand";v="99"
sec-ch-ua-mobile: ?0
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 11_2_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.146 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Sec-Fetch-Site: none
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Accept-Encoding: gzip, deflate, br
Accept-Language: zh-CN,zh;q=0.9
Cookie: OAUTHSTOKEN=52afc5806dcd00963cd5706c88f26773886fb5bdccb70f157c898f94387e85d7; BIDUPSID=B0253ED608F957045F8B002EF9D7127C; PSTM=1601466336; MCITY=-75%3A; H_WISE_SIDS=163166_161555_162685_161285_160247_163389_156286_161253_158973_162915_155226_160936_163303_161265_162371_159383_163160_159936_161421_162178_160878_157263_162943_161420_161969_127969_156927_161770_160099_161958_160897_161730_155318_161922_162283_131423_163164_162413_158982_162117_158055_163350_160801_161965_159954_160422_144966_163153_162186_154212_161230_158640_155529_155930_147551_161891_162268_162333_162816_162643_159092_162261_162156_110085_162024_163168_163317_163318_163319_163321; delPer=0; BDRCVFR[feWj1Vr5u3D]=I67x6TjHwwYf0; ZD_ENTRY=google; __yjs_duid=1_0cee4131b0d75755d3d825928b6adf4d1612428365184; BAIDUID=207F1AD9AD8E39C0DB9EC91C7FC5CD43:FG=1; BAIDUID_BFESS=715C66075E320B55829DFC57E744BB87:FG=1; H_PS_PSSID=33425_33402_33273_31253_33571_33461_33459_33318_33568; PSINO=7; BDORZ=B490B5EBF6F3CD402E515D22BCDA1598; BA_HECTOR=058g0h20852g8l24j81g21cfu0r; BDUSS=TBBTjl5TUhXcmpvR3gyV0xUYVlRTFhRRDdnMFM5U1puQXJUMmRrdGhuWENRVWhnRVFBQUFBJCQAAAAAAAAAAAEAAABvy0oa1sHT2s7Su7nKx7K70MUAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAMK0IGDCtCBgb; BDUSS_BFESS=TBBTjl5TUhXcmpvR3gyV0xUYVlRTFhRRDdnMFM5U1puQXJUMmRrdGhuWENRVWhnRVFBQUFBJCQAAAAAAAAAAAEAAABvy0oa1sHT2s7Su7nKx7K70MUAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAMK0IGDCtCBgb
`

// RedirectFunc 重定向禁止
func RedirectFunc(req *http.Request, via []*http.Request) error {
	fmt.Println(req.RequestURI)
	// 如果返回 非nil 则禁止向下重定向 返回nil 则 一直向下请求 10 次 重定向
	return http.ErrUseLastResponse
}

// 获取授权页网址
func (a *Auth) OAuthUrl4(cookie string) (ret map[string]interface{}, err error) {
	var resp1 httpclient.HttpResponse
	{
		v := url.Values{}
		v.Add("response_type", "token")
		v.Add("client_id", a.ClientID)
		v.Add("redirect_uri", "oob")
		v.Add("scope", "basic,netdisk")
		// v.Add("state", "STATE")
		query := v.Encode()

		// https://openapi.baidu.com/oauth/2.0/authorize?
		//  	response_type=token&
		//  	client_id=Va5yQRHlA4Fq4eR3LT0vuXV4&
		//  	redirect_uri=http%3A%2F%2Fwww.example.com%2Foauth_redirect&
		//  	scope=email&
		//  	display=popup&
		//  	state=xxx
		oAuthURL := conf.BaiduOpenApiDomain + OAuthUri + "?" + query
		fmt.Println("auth url:", oAuthURL)
		header := map[string]string{
			"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 11_2_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.146 Safari/537.36",
			"Accept":     `text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9`,
			"Cookie":     cookie,
		}
		client := &http.Client{CheckRedirect: RedirectFunc}
		var newReq *http.Request
		newReq, err = http.NewRequest(http.MethodGet, oAuthURL, nil)
		if nil != err {
			log.Println(err)
			return
		}

		for k, v := range header {
			newReq.Header.Set(k, v)
		}
		resp, err1 := client.Do(newReq)

		// resp1, err = httpclient.Get(oAuthURL, header)
		if err = err1; err != nil {
			log.Println("httpclient.Get failed, err:", err)
			return
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 400 {
			err = fmt.Errorf("HttpStatusCode is not equal to 200, httpStatusCode[%d], respBody[%s]",
				resp1.StatusCode, resp1.Body)
			log.Fatalln(err)
		}
		//log.Printf("Header:%+v, body:%+v\n", resp.Header, body)

		defer resp.Body.Close()
		bodyGet, err1 := ioutil.ReadAll(resp.Body)
		if err = err1; err != nil {
			log.Println(err)
			return
		}
		fmt.Printf("Get oAuthUrl, header:%+v \nresp:%s\n", resp.Header, string(bodyGet))
	}

	if err = json.Unmarshal(resp1.Body, &ret); err != nil {
		log.Println("httpclient.Get failed, ret:", string(resp1.Body))
		return
	}

	// fmt.Println("code url:", ret1.QrcodeURL)
	return ret, nil
}

func Login(username, password string) (cookie string, err error) {
	line := liner.NewLiner()
	line.SetMultiLineMode(true)
	line.SetCtrlCAborts(true)

	if username == "" {
		username, err = line.Prompt("请输入百度用户名(手机号/邮箱/用户名), 回车键提交 > ")
		if err != nil {
			log.Println("err:", err)
			return
		}
	}

	if password == "" {
		// liner 的 PasswordPrompt 不安全, 拆行之后密码就会显示出来了
		fmt.Printf("请输入密码(输入的密码无回显, 确认输入完成, 回车提交即可) > ")
		password, err = line.PasswordPrompt("")
		if err != nil {
			log.Println("err:", err)
			return
		}
	}

	bc := baidulogin.NewBaiduClinet()
	var vcode_raw, vcode, vcodestr string

	savePath := filepath.Join(os.TempDir(), "captcha.png")
	defer func() {
		os.Remove(savePath)
	}()

for_1:
	for i := 0; i < 10; i++ {
	BEGIN:
		lj := bc.BaiduLogin(username, password, vcode_raw, vcodestr)
		switch lj.ErrInfo.No {
		case "0": // 登录成功, 退出循环
			cookie = lj.Data.CookieString
			return
		case "400023", "400101": // 需要验证手机或邮箱
			fmt.Printf("\n需要验证手机或邮箱才能登录\n选择一种验证方式\n")
			fmt.Printf("1: 手机: %s\n", lj.Data.Phone)
			fmt.Printf("2: 邮箱: %s\n", lj.Data.Email)
			fmt.Printf("\n")

			var verifyType string
			for et := 0; et < 3; et++ {
				verifyType, err = line.Prompt("请输入验证方式 (1 或 2) > ")
				if err != nil {
					log.Println("err:", err)
					return
				}

				switch verifyType {
				case "1":
					verifyType = "mobile"
				case "2":
					verifyType = "email"
				default:
					fmt.Printf("[%d/3] 验证方式不合法\n", et+1)
					continue
				}
				break
			}
			if verifyType != "mobile" && verifyType != "email" {
				err = fmt.Errorf("验证方式不合法")
				log.Println("err:", err)
				return
			}
			msg := ""
			if lj.Data.AuthID != "" {
				msg = bc.SendCodeToUser(verifyType, lj.Data.VerifyURL, lj.Data.AuthID) // 发送验证码
			} else {
				msg = bc.SendCodeToUser2(verifyType, lj.Data.Token)
			}
			fmt.Printf("消息: %s\n\n", msg)
			if strings.Contains(msg, "系统出错") {
				log.Println("msg:", msg)
				return
			}
			for et := 0; et < 3; et++ {
				vcode, err = line.Prompt("请输入接收到的验证码 > ")
				if err != nil {
					log.Println("err:", err)
					return
				}
				nlj := &baidulogin.LoginJSON{}
				if lj.Data.AuthID != "" {
					// 此处 BDUSS 等信息尚未获取到, 仅仅完成了邮箱/电话验证
					nlj = bc.VerifyCode(vcode, verifyType, lj.Data.VerifyURL, lj.Data.AuthID, lj.Data.LoginProxy, lj.Data.AuthSID)
				} else {
					// 此处 BDUSS 等信息已在请求中返回
					nlj = bc.VerifyCode2(verifyType, lj.Data.Token, vcode, lj.Data.U)
				}
				if nlj.ErrInfo.No != "0" {
					fmt.Printf("[%d/3] 错误消息: %s\n\n", et+1, nlj.ErrInfo.Msg)
					if nlj.ErrInfo.No == "-2" { // 需要重发验证码
						log.Println("err:", nlj.ErrInfo)
						return
					}
					continue
				} else {
					vcode_raw = ""
					vcodestr = ""
					goto BEGIN
				}
				// 登录成功
				cookie = lj.Data.CookieString
				// nlj.Data.BDUSS, nlj.Data.PToken, nlj.Data.SToken, nlj.Data.CookieString, nil
				return
			}
			break for_1
		case "500001", "500002": // 验证码
			fmt.Printf("\n%s\n", lj.ErrInfo.Msg)
			vcodestr = lj.Data.CodeString
			if vcodestr == "" {
				err = fmt.Errorf("未找到codeString")
				log.Println("err:", err)
				return
			}

			// 图片验证码
			var (
				verifyImgURL = "https://wappass.baidu.com/cgi-bin/genimage?" + vcodestr
			)

			err = handleVerifyImg(savePath, verifyImgURL)
			if err != nil {
				fmt.Println(err)
			} else {
				fmt.Printf("打开以下路径, 以查看验证码\n%s\n\n", savePath)
			}

			fmt.Printf("或者打开以下的网址, 以查看验证码\n")
			fmt.Printf("%s\n\n", verifyImgURL)

			vcode_raw, err = line.Prompt("请输入验证码 > ")
			if err != nil {
				log.Println("err:", err)
				return
			}
			continue
		default:
			err = fmt.Errorf("错误代码: %s, 消息: %s", lj.ErrInfo.No, lj.ErrInfo.Msg)
			log.Println("err:", err)
			return
		}
	}
	return
}

// handleVerifyImg 处理验证码, 下载到本地
func handleVerifyImg(imgURL string, savePath string) (err error) {
	imgContents, err := requester.Fetch("GET", imgURL, nil, nil)
	if err != nil {
		return fmt.Errorf("获取验证码失败, 错误: %s", err)
	}

	_, err = png.Decode(bytes.NewReader(imgContents))
	if err != nil {
		return fmt.Errorf("验证码解析错误: %s", err)
	}

	return ioutil.WriteFile(savePath, imgContents, 0777)
}

func showImg(imgURL string) {
	imgContents, err := requester.Fetch("GET", imgURL, nil, nil)
	if err != nil {
		//  fmt.Errorf("获取验证码失败, 错误: %s", err)
	}
	_ = imgContents
}
