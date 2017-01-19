# Copyright 2016 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

from page_sets.system_health import platforms
from page_sets.system_health import system_health_story

from page_sets.login_helpers import dropbox_login
from page_sets.login_helpers import google_login

from telemetry import decorators


class _LoadingStory(system_health_story.SystemHealthStory):
  """Abstract base class for single-page System Health user stories."""
  ABSTRACT_STORY = True


################################################################################
# Search and e-commerce.
################################################################################
# TODO(petrcermak): Split these into 'portal' and 'shopping' stories.


class LoadGoogleStory(_LoadingStory):
  NAME = 'load:search:google'
  URL = 'https://www.google.co.uk/'


class LoadBaiduStory(_LoadingStory):
  NAME = 'load:search:baidu'
  URL = 'https://www.baidu.com/s?word=google'


class LoadYahooStory(_LoadingStory):
  NAME = 'load:search:yahoo'
  URL = 'https://search.yahoo.com/search;_ylt=?p=google'


class LoadAmazonStory(_LoadingStory):
  NAME = 'load:search:amazon'
  URL = 'https://www.amazon.com/s/?field-keywords=nexus'


class LoadTaobaoDesktopStory(_LoadingStory):
  NAME = 'load:search:taobao'
  URL = 'https://world.taobao.com/'
  SUPPORTED_PLATFORMS = platforms.DESKTOP_ONLY


class LoadTaobaoMobileStory(_LoadingStory):
  NAME = 'load:search:taobao'
  # "ali_trackid" in the URL suppresses "Download app" interstitial.
  URL = 'http://m.intl.taobao.com/?ali_trackid'
  SUPPORTED_PLATFORMS = platforms.MOBILE_ONLY


class LoadYandexStory(_LoadingStory):
  NAME = 'load:search:yandex'
  URL = 'https://yandex.ru/touchsearch?text=science'


class LoadEbayStory(_LoadingStory):
  NAME = 'load:search:ebay'
  # Redirects to the "http://" version.
  URL = 'https://www.ebay.com/sch/i.html?_nkw=headphones'


################################################################################
# Social networks.
################################################################################


class LoadFacebookStory(_LoadingStory):
  # Using Facebook login often causes "404 Not Found" with WPR.
  NAME = 'load:social:facebook'
  URL = 'https://www.facebook.com/rihanna'


class LoadTwitterStory(_LoadingStory):
  NAME = 'load:social:twitter'
  URL = 'https://www.twitter.com/nasa'


class LoadVkStory(_LoadingStory):
  NAME = 'load:social:vk'
  URL = 'https://vk.com/sbeatles'
  # Due to the deterministic date injected by WPR (February 2008), the cookie
  # set by https://vk.com immediately expires, so the page keeps refreshing
  # indefinitely on mobile
  # (see https://github.com/chromium/web-page-replay/issues/71).
  SUPPORTED_PLATFORMS = platforms.DESKTOP_ONLY


class LoadInstagramStory(_LoadingStory):
  NAME = 'load:social:instagram'
  URL = 'https://www.instagram.com/selenagomez/'


class LoadPinterestStory(_LoadingStory):
  NAME = 'load:social:pinterest'
  URL = 'https://uk.pinterest.com/categories/popular/'


class LoadTumblrStory(_LoadingStory):
  NAME = 'load:social:tumblr'
  # Redirects to the "http://" version.
  URL = 'https://50thousand.tumblr.com/'


################################################################################
# News, discussion and knowledge portals and blogs.
################################################################################


class LoadBbcStory(_LoadingStory):
  NAME = 'load:news:bbc'
  # Redirects to the "http://" version.
  URL = 'https://www.bbc.co.uk/news/world-asia-china-36189636'


class LoadCnnStory(_LoadingStory):
  NAME = 'load:news:cnn'
  # Using "https://" shows "Your connection is not private".
  URL = 'http://edition.cnn.com'


class LoadFlipboardStory(_LoadingStory):
  NAME = 'load:news:flipboard'
  URL = 'https://flipboard.com/explore'


class LoadHackerNewsStory(_LoadingStory):
  NAME = 'load:news:hackernews'
  URL = 'https://news.ycombinator.com'


class LoadNytimesDesktopStory(_LoadingStory):
  NAME = 'load:news:nytimes'
  URL = 'http://www.nytimes.com'
  SUPPORTED_PLATFORMS = platforms.DESKTOP_ONLY


class LoadNytimesMobileStory(_LoadingStory):
  NAME = 'load:news:nytimes'
  URL = 'http://mobile.nytimes.com'
  SUPPORTED_PLATFORMS = platforms.MOBILE_ONLY


class LoadQqMobileStory(_LoadingStory):
  NAME = 'load:news:qq'
  # Using "https://" hangs and shows "This site can't be reached".
  URL = 'http://news.qq.com'


class LoadRedditDesktopStory(_LoadingStory):
  NAME = 'load:news:reddit'
  URL = 'https://www.reddit.com/r/news/top/?sort=top&t=week'
  SUPPORTED_PLATFORMS = platforms.DESKTOP_ONLY


class LoadRedditMobileStory(_LoadingStory):
  NAME = 'load:news:reddit'
  URL = 'https://www.reddit.com/r/news/top/?sort=top&t=week'
  SUPPORTED_PLATFORMS = platforms.MOBILE_ONLY


class LoadSohuMobileStory(_LoadingStory):
  NAME = 'load:news:sohu'
  # Using "https://" leads to missing images and scripts on mobile (due to
  # mixed content).
  URL = 'http://m.sohu.com/n/447433356/'
  # The desktop page (http://news.sohu.com/20160503/n447433356.shtml) almost
  # always fails to completely load due to
  # https://github.com/chromium/web-page-replay/issues/74.
  SUPPORTED_PLATFORMS = platforms.MOBILE_ONLY


class LoadWashingtonPostMobileStory(_LoadingStory):
  NAME = 'load:news:washingtonpost'
  URL = 'https://www.washingtonpost.com/pwa'
  SUPPORTED_PLATFORMS = platforms.MOBILE_ONLY
  _CLOSE_BUTTON_SELECTOR = '.close'

  def _DidLoadDocument(self, action_runner):
    # Close the popup window. On Nexus 9 (and probably other tables) the popup
    # window does not have a "Close" button, instead it has only a "Send link
    # to phone" button. So on tablets we run with the popup window open. The
    # popup is transparent, so this is mostly an aesthetical issue.
    has_button = action_runner.EvaluateJavaScript(
        '!!document.querySelector({{ selector }})',
        selector=self._CLOSE_BUTTON_SELECTOR)
    if has_button:
      action_runner.ClickElement(selector=self._CLOSE_BUTTON_SELECTOR)


class LoadWikipediaStory(_LoadingStory):
  NAME = 'load:news:wikipedia'
  URL = 'https://en.wikipedia.org/wiki/Science'


################################################################################
# Audio, images, and video.
################################################################################


class LoadYouTubeStory(_LoadingStory):
  # No way to disable autoplay on desktop.
  NAME = 'load:media:youtube'
  URL = 'https://www.youtube.com/watch?v=QGfhS1hfTWw&autoplay=false'


class LoadDailymotionStory(_LoadingStory):
  # The side panel with related videos doesn't show on desktop due to
  # https://github.com/chromium/web-page-replay/issues/74.
  NAME = 'load:media:dailymotion'
  URL = (
      'https://www.dailymotion.com/video/x489k7d_street-performer-shows-off-slinky-skills_fun?autoplay=false')


class LoadGoogleImagesStory(_LoadingStory):
  NAME = 'load:media:google_images'
  URL = 'https://www.google.co.uk/search?tbm=isch&q=love'


class LoadSoundCloudStory(_LoadingStory):
  # No way to disable autoplay on desktop. Album artwork doesn't load due to
  # https://github.com/chromium/web-page-replay/issues/73.
  NAME = 'load:media:soundcloud'
  URL = 'https://soundcloud.com/lifeofdesiigner/desiigner-panda'


class Load9GagStory(_LoadingStory):
  NAME = 'load:media:9gag'
  URL = 'https://www.9gag.com/'


class LoadFlickrStory(_LoadingStory):
  NAME = 'load:media:flickr'
  URL = 'https://www.flickr.com/photos/tags/farm'

  def _DidLoadDocument(self, action_runner):
    # Wait until the 'Recently tagged' view loads.
    action_runner.WaitForJavaScriptCondition('''
        document.querySelector(
            '.search-photos-everyone-trending-view .photo-list-view')
                !== null''')


class LoadImgurStory(_LoadingStory):
  NAME = 'load:media:imgur'
  URL = 'http://imgur.com/gallery/5UlBN'


class LoadFacebookPhotosMobileStory(_LoadingStory):
  NAME = 'load:media:facebook_photos'
  URL = (
      'https://m.facebook.com/rihanna/photos/a.207477806675.138795.10092511675/10153911739606676/?type=3&source=54&ref=page_internal')
  SUPPORTED_PLATFORMS = platforms.MOBILE_ONLY


class LoadFacebookPhotosDesktopStory(_LoadingStory):
  NAME = 'load:media:facebook_photos'
  URL = (
      'https://www.facebook.com/rihanna/photos/a.207477806675.138795.10092511675/10153911739606676/?type=3&theater')
  # Recording currently does not work. The page gets stuck in the
  # theater viewer.
  SUPPORTED_PLATFORMS = platforms.NO_PLATFORMS


################################################################################
# Online tools (documents, emails, storage, ...).
################################################################################


class LoadDocsStory(_LoadingStory):
  NAME = 'load:tools:docs'
  URL = (
      'https://docs.google.com/document/d/1GvzDP-tTLmJ0myRhUAfTYWs3ZUFilUICg8psNHyccwQ/edit?usp=sharing')


class _LoadGmailBaseStory(_LoadingStory):
  NAME = 'load:tools:gmail'
  URL = 'https://mail.google.com/mail/'
  ABSTRACT_STORY = True

  def _Login(self, action_runner):
    google_login.LoginGoogleAccount(action_runner, 'googletest',
                                    self.credentials_path)

    # Navigating to https://mail.google.com immediately leads to an infinite
    # redirection loop due to a bug in WPR (see
    # https://github.com/chromium/web-page-replay/issues/70). We therefore first
    # navigate to a sub-URL to set up the session and hit the resulting
    # redirection loop. Afterwards, we can safely navigate to
    # https://mail.google.com.
    action_runner.tab.WaitForDocumentReadyStateToBeComplete()
    action_runner.Navigate(
        'https://mail.google.com/mail/mu/mp/872/trigger_redirection_loop')
    action_runner.tab.WaitForDocumentReadyStateToBeComplete()


class LoadGmailDesktopStory(_LoadGmailBaseStory):
  SUPPORTED_PLATFORMS = platforms.DESKTOP_ONLY

  def _DidLoadDocument(self, action_runner):
    # Wait until the UI loads.
    action_runner.WaitForJavaScriptCondition(
        'document.getElementById("loading").style.display === "none"')


@decorators.Disabled('android')  # crbug.com/657433
class LoadGmailMobileStory(_LoadGmailBaseStory):
  SUPPORTED_PLATFORMS = platforms.MOBILE_ONLY

  def _DidLoadDocument(self, action_runner):
    # Wait until the UI loads.
    action_runner.WaitForElement('#apploadingdiv')
    action_runner.WaitForJavaScriptCondition(
        'document.getElementById("apploadingdiv").style.height === "0px"')

class LoadMapsStory(_LoadingStory):
  NAME = 'load:tools:maps'
  URL = 'https://www.google.com/maps/place/London,+UK/'


class LoadStackOverflowStory(_LoadingStory):
  NAME = 'load:tools:stackoverflow'
  URL = (
      'https://stackoverflow.com/questions/36827659/compiling-an-application-for-use-in-highly-radioactive-environments')


class LoadDropboxStory(_LoadingStory):
  NAME = 'load:tools:dropbox'
  URL = 'https://www.dropbox.com'

  def _Login(self, action_runner):
    dropbox_login.LoginAccount(action_runner, 'dropbox', self.credentials_path)


class LoadWeatherStory(_LoadingStory):
  NAME = 'load:tools:weather'
  URL = 'https://weather.com/en-GB/weather/today/l/USCA0286:1:US'


class LoadDriveStory(_LoadingStory):
  NAME = 'load:tools:drive'
  URL = 'https://drive.google.com/drive/my-drive'

  def _Login(self, action_runner):
    google_login.LoginGoogleAccount(action_runner, 'googletest',
                                    self.credentials_path)


################################################################################
# In-browser games (HTML5 and Flash).
################################################################################


class LoadBubblesStory(_LoadingStory):
  NAME = 'load:games:bubbles'
  URL = (
      'https://games.cdn.famobi.com/html5games/s/smarty-bubbles/v010/?fg_domain=play.famobi.com&fg_uid=d8f24956-dc91-4902-9096-a46cb1353b6f&fg_pid=4638e320-4444-4514-81c4-d80a8c662371&fg_beat=620')

  def _DidLoadDocument(self, action_runner):
    # The #logo element is removed right before the main menu is displayed.
    action_runner.WaitForJavaScriptCondition(
        'document.getElementById("logo") === null')


class LoadLazorsStory(_LoadingStory):
  NAME = 'load:games:lazors'
  # Using "https://" hangs and shows "This site can't be reached".
  URL = 'http://www8.games.mobi/games/html5/lazors/lazors.html'


class LoadSpyChaseStory(_LoadingStory):
  NAME = 'load:games:spychase'
  # Using "https://" shows "Your connection is not private".
  URL = 'http://playstar.mobi/games/spychase/index.php'

  def _DidLoadDocument(self, action_runner):
    # The background of the game canvas is set when the "Tap screen to play"
    # caption is displayed.
    action_runner.WaitForJavaScriptCondition(
        'document.querySelector("#game canvas").style.background !== ""')


@decorators.Disabled('mac') # crbug.com/664661
class LoadMiniclipStory(_LoadingStory):
  NAME = 'load:games:miniclip'
  # Using "https://" causes "404 Not Found" during WPR recording.
  URL = 'http://www.miniclip.com/games/en/'
  SUPPORTED_PLATFORMS = platforms.DESKTOP_ONLY  # Requires Flash.


class LoadAlphabettyStory(_LoadingStory):
  NAME = 'load:games:alphabetty'
  URL = 'https://king.com/play/alphabetty'
  SUPPORTED_PLATFORMS = platforms.DESKTOP_ONLY  # Requires Flash.
