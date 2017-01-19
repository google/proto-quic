# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

from telemetry.page import page
from telemetry import story


TOP_2013_URLS = [
  'http://www.facebook.com/barackobama',
  'https://www.google.com/search?q=barack%20obama',
  'http://youtube.com',
  'http://yahoo.com',
  'http://www.baidu.com/s?wd=barack+obama',
  'http://en.wikipedia.org/wiki/Wikipedia',
  'http://qq.com',
  'http://www.amazon.com/Kindle-Fire-Amazon-Tablet/dp/B0051VVOB2',
  'http://googleblog.blogspot.com/',
  'http://taobao.com',
  'http://www.linkedin.com/in/linustorvalds',
  'http://yahoo.co.jp',
  'http://sina.com.cn',
  'http://msn.com',
  'http://yandex.ru/yandsearch?text=barack+obama',
  'http://translation.babylon.com/',
  'http://www.bing.com/search?q=barack+obama',
  'http://wordpress.org/news/',
  'http://www.ebay.com/sch/i.html?_nkw=antiques',
  'http://163.com',
  'http://www.soso.com/q?w=barack+obama',
  'http://www.microsoft.com/en-us/default.aspx',
  'http://go.mail.ru/search?mailru=1&mg=1&q=barack+obama',
  'http://vk.com/id118712387',
  'http://staff.tumblr.com/',
  'http://sohu.com',
  'http://sfbay.craigslist.org/mis/',
  'http://www.ask.com/web?q=barack+obama&search=&qsrc=0&o=0&l=dir',
  'http://www.apple.com/ipodtouch/',
  'http://blog.pinterest.com/',
  'http://pinterest.com/backdrophome/',
  'http://paypal.com',
  'http://bbc.co.uk',
  'http://www.avg.com/us-en/avg-premium-security',
  'http://googlesystem.blogspot.com/',
  'http://tudou.com',
  'http://blog.fc2.com/en/',
  'http://imdb.com',
  'http://youku.com',
  'http://www.flickr.com/photos/thomashawk/',
  'http://www.flickr.com/photos/thomashawk/sets/72157600284219965/detail/',
   # pylint: disable=line-too-long
  'http://search.yahoo.com/search?ei=UTF-8&trackingType=go_search_home&p=barack+obama&fr=hsusgo1&sa.x=0&sa.y=0',
  'http://www.conduit.com/',
  'http://ifeng.com',
  'http://tmall.com',
  'http://hao123.com',
  'http://aol.com',
  'http://zedo.com',
   # pylint: disable=line-too-long
  'http://search.mywebsearch.com/mywebsearch/GGmain.jhtml?searchfor=barack+obama',
  'http://cnn.com',
  'http://portal.ebay.de/deutschland-schraubt-angebote',
  'http://www.adobe.com/products/photoshopfamily.html?promoid=JOLIW',
  'http://global.rakuten.com/us/',
  # pylint: disable=line-too-long
  'http://laundry.about.com/od/kidsandlaundry/f/How-Do-I-Wash-A-Backpack.htm',
  'http://thepiratebay.se/search/barack%20obama/0/99/0',
  'http://360buy.com',
  'http://huffingtonpost.com',
  'http://alibaba.com',
  'http://chinaz.com',
  'http://www.sogou.com/web?query=barack+obama',
  # pylint: disable=line-too-long
  ('http://www.amazon.de/gp/product/B0051QVF7A/ref=amb_link_170625867_1/'
   '275-4711375-4099801?ie=UTF8&nav_sdd=aps&pf_rd_m=A3JWKAKR8XB7XF&'
   'pf_rd_s=center-1&pf_rd_r=1C0XDBPB12WHDM63V11R&pf_rd_t=101&pf_rd_p'
   '=320475427&pf_rd_i=301128'),
  'http://google.pl',
  'http://mediafire.com',
  'http://espn.go.com',
  'http://uol.com.br',
  'http://www.godaddy.com/products/secure-hosting.aspx?ci=72738',
  'http://imgur.com/gallery/b90ZE',
  'http://home.alipay.com/bank/paymentKJ.htm',
  'http://amazon.co.jp',
  # pylint: disable=line-too-long
  'http://stackoverflow.com/questions/11227809/why-is-processing-a-sorted-array-faster-than-an-unsorted-array',
  'http://www.google.com/doubleclick/',
  'http://search.4shared.com/q/CCAD/1/barack%20obama',
  'http://dailymotion.com',
  'http://globo.com',
  'http://instagram.com/developer/',
  'http://livedoor.com',
  'http://wordpress.org/showcase/',
  'http://bp.blogspot.com',
  'http://wigetmedia.com/advertisers',
  'http://www.search-results.com/web?&q=barack%20obama',
  'http://cnet.com',
  'http://nytimes.com',
  'http://torrentz.eu/search?f=barack+obama',
  'http://livejournal.com',
  'http://douban.com',
  'http://www.weather.com/weather/right-now/Mountain+View+CA+94043',
  'http://dailymail.co.uk',
  'http://www.tianya.cn/bbs/index.shtml',
  'http://ehow.com',
  'http://theproject.badoo.com/final.phtml',
  # pylint: disable=line-too-long
  'http://www.bankofamerica.com/deposits/checksave/index.cfm?template=check_eBanking',
  'http://vimeo.com',
  'http://360.cn',
  'http://indiatimes.com',
  'http://deviantart.com',
  'http://reddit.com',
  'http://aweber.com',
  'http://warriorforum.com',
  'http://spiegel.de',
  'http://pconline.com.cn',
  'http://mozilla.org',
  'http://booking.com',
  'http://goo.ne.jp',
  'https://www.chase.com/online/Home-Lending/mortgages.htm',
  'http://addthis.com',
  'http://56.com',
  'http://news.blogfa.com/',
  'http://www.stumbleupon.com/jobs',
  'https://www.dropbox.com/about',
  'http://www.clicksor.com/publishers/adformat',
  'http://answers.com',
  'http://en.softonic.com/',
  'http://walmart.com',
  'http://pengyou.com',
  'http://outbrain.com',
  'http://comcast.net',
  'http://foxnews.com',
  'http://photobucket.com/findstuff/photography%20styles/',
  'http://bleach.wikia.com/?redirect=no',
  'http://sourceforge.net/projects/xoops/?source=frontpage&position=1',
  'http://onet.pl',
  'http://guardian.co.uk',
  # pylint: disable=line-too-long
  'https://www.wellsfargo.com/jump/enterprise/doublediscount?msc=5589&mplx=10918-70119-3408-64',
  'http://wikimediafoundation.org/wiki/Home',
  'http://xunlei.com',
  'http://as.58.com/shuma/',
  'http://skype.com',
  'http://etsy.com',
  'http://bild.de',
  # pylint: disable=line-too-long
  'http://search.naver.com/search.naver?where=nexearch&query=barack+obama&sm=top_hty&fbm=0&ie=utf8',
  'http://statcounter.com/features/?PHPSESSID=bbjcvjr681bcul4vqvgq2qgmo7',
  'http://iqiyi.com',
  'http://fbcdn.net',
  'http://www.myspace.com/browse/people',
  'http://allegro.pl/antyki-i-sztuka',
  'http://yesky.com',
  'http://justbeenpaid.com',
  'http://adultfriendfinder.com',
  'http://fiverr.com',
  'http://www.leboncoin.fr/annonces/offres/centre/',
  'http://dictionary.reference.com/',
  'http://realtime.rediff.com/instasearch#!barack%20obama',
  'http://zol.com.cn',
  'http://optmd.com',
  'http://www.filestube.com/search.html?q=barack+obama&select=All',
  'http://xinhuanet.com',
  'http://www.salesforce.com/sales-cloud/overview/',
  # pylint: disable=line-too-long
  'http://www.squidoo.com/make-cards-and-gift-bags-with-antique-photos',
  'http://www.domaintools.com/research/',
  'http://download.cnet.com/windows/?tag=hdr;brandnav',
  'https://rapidshare.com/#!shop',
  'http://people.com.cn',
  'http://ucoz.ru',
  'http://free.fr',
  'http://nicovideo.jp',
  # pylint: disable=line-too-long
  'http://www.yelp.com/search?find_desc=food&find_loc=San+Jose%2C+CA&ns=1',
  'http://slideshare.net',
  'http://archive.org/web/web.php',
  'http://www.cntv.cn/index.shtml',
  'http://english.cntv.cn/01/index.shtml',
  'http://abonnez-vous.orange.fr/residentiel/accueil/accueil.aspx',
  'http://v.it168.com/',
  'http://nbcolympics.com',
  'http://hootsuite.com',
  # pylint: disable=line-too-long
  'http://www.scribd.com/doc/52210329/The-Masters-Augusta-National-s-Amen-Corner-up-close',
  'http://themeforest.net',
  'http://4399.com',
  'http://www.soku.com/v?keyword=barack%20obama',
  'http://google.se',
  'http://funmoods.com',
  'http://csdn.net',
  'http://telegraph.co.uk',
  'http://taringa.net',
  # pylint: disable=line-too-long
  'http://www.tripadvisor.com/Tourism-g32701-Mendocino_California-Vacations.html',
  'http://pof.com',
  'http://wp.pl',
  'http://soundcloud.com/flosstradamus/tracks',
  'http://w3schools.com/html/default.asp',
  'http://ameblo.jp/staff/',
  'http://wsj.com',
  'http://web.de',
  'http://sweetim.com',
  'http://rambler.ru',
  'http://gmx.net',
  'http://www.indeed.com/jobs?q=software&l=Mountain+View%2C+CA',
  'http://ilivid.com',
  'http://www.xing.com/search/people?search%5Bq%5D=lufthansa',
  'http://reuters.com',
  'http://hostgator.com',
  'http://www.ikea.com/us/en/catalog/categories/departments/living_room/',
  'http://www.kaixin001.com/award2012/wenming/index.php',
  'http://ku6.com',
  'http://libero.it',
  'http://samsung.com',
  'http://hudong.com',
  'http://espncricinfo.com',
  'http://china.com',
  # pylint: disable=line-too-long
  'http://www.ups.com/content/us/en/bussol/browse/smallbiz/new-to-ups.html?WT.svl=SolExp',
  'http://letv.com',
  'http://ero-advertising.com',
  'http://mashable.com',
  'http://iminent.com',
  'http://rutracker.org',
  # pylint: disable=line-too-long
  'http://www.shopping.hp.com/en_US/home-office/-/products/Laptops/Laptops',
  # pylint: disable=line-too-long
  'http://www.clickbank.com/buy_products.htm?dores=true&mainCategoryId=1340&sortField=POPULARITY&b1=1340',
  'http://b.hatena.ne.jp/',
  # pylint: disable=line-too-long
  'http://www.youdao.com/search?q=barack+obama&ue=utf8&keyfrom=web.index',
  'http://forbes.com',
  'http://nbcnews.com',
  'http://bitauto.com',
  'http://php.net',
  'http://www.target.com/c/women/-/N-5xtd3#?lnk=nav_t_spc_1_0',
  'http://dianxin.cn',
  'http://www.aizhan.com/siteall/www.youboy.com/',
  'http://veiculos-home.mercadolivre.com.br/',
  'http://kakaku.com',
  'http://flipkart.com',
  'http://paipai.com'
  ]


class Top2012Q3Page(page.Page):

  def __init__(self, url, ps):
    super(Top2012Q3Page, self).__init__(
        url=url, page_set=ps, credentials_path = 'data/credentials.json',
        name=url[:140])  # Make sure page's name is not too long
    self.archive_data_file = 'data/2012Q3.json'

  def RunPageInteractions(self, action_runner):
    with action_runner.CreateGestureInteraction('ScrollAction'):
      action_runner.ScrollPage()


class Top2012Q3PageSet(story.StorySet):
  """ Pages hand-picked from top-lists in Q32012. """

  def __init__(self):
    super(Top2012Q3PageSet, self).__init__(
      archive_data_file='data/2012Q3.json',
      cloud_storage_bucket=story.PARTNER_BUCKET)


    for url in TOP_2013_URLS:
      self.AddStory(Top2012Q3Page(url, self))
