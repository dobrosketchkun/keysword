from bs4 import BeautifulSoup
import requests
from requests import ReadTimeout, ConnectTimeout, HTTPError, Timeout, ConnectionError
import re
import json
import time
import hashlib
from fake_headers import Headers
import sys
import argparse
try:
	import argon2
	def time2(keyword): 
		return argon2.low_level.hash_secret(keyword.encode(), hashlib.sha256(keyword.encode()).digest(),time_cost=3, memory_cost=502400, parallelism=1, hash_len=64, type=argon2.low_level.Type.ID)
except:
	#print('Argon2 is not available, sha000 is enabled.')
	def time2(password = 'this is not a password, dummy', circles = 15):
		for times in range(circles):
			cond = 1
			counter = 0
			while cond:
				sha256 = str(hashlib.sha256(password.encode()).hexdigest())
				if sha256[0:4] == '0000':
					cond = 0
					result = sha256 
				else:
					password = sha256
					counter += 1
			password = result
		return result

def progress(count, total, status=''):
    bar_len = 60
    filled_len = int(round(bar_len * count / float(total)))

    percents = round(100.0 * count / float(total), 1)
    bar = '=' * filled_len + '-' * (bar_len - filled_len)

    sys.stdout.write('[%s] %s%s ...%s\r' % (bar, percents, '%', status))
    sys.stdout.flush()

#.encode('utf-8')



headers = Headers(os="mac", headers=True).generate()

# headers = {'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) ' 
                      # 'AppleWebKit/537.11 (KHTML, like Gecko) '
                      # 'Chrome/23.0.1271.64 Safari/537.11',
        # 'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        # 'Accept-Charset': 'ISO-8859-1,utf-8;q=0.7,*;q=0.3',
        # 'Accept-Encoding': 'none',
        # 'Accept-Language': 'en-US,en;q=0.8',
        # 'Connection': 'keep-alive'}

# keyword = 'wall organizer'
# keyword = 'paper straws'
# keyword = 'tactical pen'
# keyword = 'hangers for clothes'


parser = argparse.ArgumentParser()
parser.add_argument("-k", "--keywords", type=str,
					help='''For search on Amazon.
If the keyword consits of two or more words you shold use ".
Example: "This is a test keywords"''')
parser.add_argument("-p", "--pages", default=1, type= int, help="Number of the page to fetch")

args = parser.parse_args()
keyword = args.keywords
pages = args.pages
# pages = 1




table = [['Name','Brand', 'Category', 'Rank', 'Reviews','Stars','Sales','Revenue','Amazon Price','Ebay Price', 'Amazon Link', 'Ebay Link']]



def amazon_search(keyword, page):
	return 'https://www.amazon.com/s?k=' + keyword.replace(' ', '+') +'&page=' + str(page)


def soup_creator(url):
	try:
		res = requests.get(url, headers=headers)
		res.raise_for_status()
	except (ConnectTimeout, HTTPError, ReadTimeout, Timeout, ConnectionError):
		res = requests.get(url, headers=headers)
		res.raise_for_status()
	return BeautifulSoup(res.text.encode('utf-8'), 'lxml')

asearch = amazon_search(keyword, pages)

asoup = soup_creator(asearch)



all = asoup.findAll('h2', {'class': 'a-size-mini a-spacing-none a-color-base s-line-clamp-4'})


count = 0
for _all in all:
	progress(count, len(all), status='Fetching items...')
	count += 1
	#print('Count:', str(count))
	time2(keyword)
	# try:
	#--------------------------------------------------------------------------------------
	# ONE PARTICULAR LINK

	# link_t = all[0].findAll('a', {'class':'a-link-normal a-text-normal'})[0]['href']
	link_t = _all.findAll('a', {'class':'a-link-normal a-text-normal'})[0]['href']
	link = 'https://amazon.com' + link_t

	asoup_item = soup_creator(link)
	
	try:	#Trying to find ebay price and link
		asin = str(asoup_item).split('.pageAsin = "')[1].split('";')[0]


		keepa_url = 'https://dyn.keepa.com/r/?type=ebay&user=a50bbce16565c06ee3696300c2fdb04c958476bca0aa0a5c96c85cf3d4e3e38c&domain=1&asin='+asin+'&search=1&source=website&path=28'
		res = requests.get(keepa_url, headers=headers)
		res.raise_for_status()

		ebay_url = str(res.text).split('<div class="lvpic pic img left"')[1].split('  class="img')[0].split('<a href="')[-1]
		res = requests.get(ebay_url, headers=headers)
		res.raise_for_status()

		ebay_price = str(res.text).split('itemprop="price"  style="" content="')[1].split('">')[0]
		#print(ebay_price)
	except:
		ebay_url = 'None'
		ebay_price = 'None'



	#print('Getting item...')
	if 'To discuss automated access to Amazon data please contact api-services-support@amazon.com' in str(asoup_item):
		print('Oops, busted. Waiting.')
		time2(keyword)
		continue
		

	# with open(str(count)+'.txt','w') as file:
		# file.write(link)
		# file.write(str(asoup_item.encode('utf-8')))
		
	if 'Available from' in str(asoup_item):
		#print('Weell, it\'s not a goood item, skip.')
		continue

	def estimated(asoup_item):
		headers = {'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) ' 
						  'AppleWebKit/537.11 (KHTML, like Gecko) '
						  'Chrome/23.0.1271.64 Safari/537.11',
			'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
			'Accept-Charset': 'ISO-8859-1,utf-8;q=0.7,*;q=0.3',
			'Accept-Encoding': 'none',
			'Accept-Language': 'en-US,en;q=0.8',
			'Connection': 'keep-alive',
			'Referer': 'https://amzscout.net/sales-estimator/'}
		
		search_left = str(asoup_item).split('Best Sellers Rank')
		search_right = search_left[1].split('(<a href="')
		search_rank = search_right[0].split('#')[1]
 
		rank, category = search_rank.split(' in ')
		category = category.replace('&amp;','&')
		#print(rank, category)
		rank = rank.replace(',','')
		url = 'https://amzscout.net/estimator/v1/sales?domain=COM&category=' + category.strip().replace(' ','%20').replace('&','%26') + '&rank=' + rank 
		ses = requests.Session() 
		amzs = ses.get('https://amzscout.net/analytics/v1/events', headers=headers )
		try:
			res = ses.get(url, headers=headers)
			res.raise_for_status()
		except (ConnectTimeout, HTTPError, ReadTimeout, Timeout, ConnectionError):
			res = ses.get(url, headers=headers)
			res.raise_for_status()
			
		sales = json.loads(res.text)['sales'] #Sales per month
		try:
			try:
				try:
					price_right_side = str(asoup_item.findAll('span', {'class':'a-offscreen'})).split('<span class="a-offscreen">')
					price = float(price_right_side[1].split('</span>')[0][1:]) #Price
				except:

					price_right_side = str(asoup_item).split('twisterSwatchPrice"> ')
					
					price_left_side = price_right_side[1].split('</span>')
					#print(pr, '!!!!')
					price = float(price_left_side[0][1:]) #Price
			except:
				# "price_inside_buybox">\n        $8.99\n    </span>
					price_right_side = str(asoup_item).split('"price_inside_buybox">\n        ')
					price_left_side = price_right_side[1].split('\n    </span>')
					price = float(price_left_side[0][1:]) #Price
		except:
			# price_right_side = str(asoup_item).split('data-asin-price="')
			price_right_side = str(asoup_item).split('"price":')
			price_left_side = price_right_side[1].split(',')
			price = float(price_left_side[0]) #Price

		return rank, category.strip(),str(price), sales, int(int(sales)*price),
	try:
		rank, category, price, sales, revenue = estimated(asoup_item)
	except:
		continue 
	
	# try:
		# name_right_side = str(asoup_item).split('<title>Amazon.com')
		# name = name_right_side[1].split('</title>')[0] #Name of the item
		# name = name.replace(' -','').replace('&amp;','&')
	# except:
		# name_right_side = str(asoup_item).split('meta content="Amazon.com : ')
		# name = name_right_side[1].split('" name="description"')[0] #Name of the item
		

	name_right_side = str(asoup_item).split('"Buy now:')
	name = name_right_side[1].split('"')[0] #Name of the item
	name = name.replace(';','.').replace('&amp;','&')

	reviews_right_side = str(asoup_item).split('"total-review-count">')
	reviews = reviews_right_side[1].split('</h2></a>')[0] #Reviews
	try:
		reviews = reviews.split(' customer review')[0]
	except:
		reviews = reviews.split(' customer reviews')[0]

	try:
		try:
			stars_right_side = str(asoup_item).split('id="acrPopover" title="')
			stars = stars_right_side[1].split('">')[0] #Rating

		except:
			stars_right_side = str(asoup_item).split('\n</a>\n</div>\n<br/>\n  ')
			stars = stars_right_side[1].split('\n  </td>\n</tr>\n<tr>\n')[0] 
	except:
		stars = 'Error' #TODO - Make it right
		
	stars = stars.split(' out of')[0]
	try:
		brand_right_side = str(asoup_item).split('id="bylineInfo">') 
		brand = brand_right_side[1].split('</a>')[0] #Brand
		try:
			brand  = brand.split('">"')[-1]
		except:
			pass
	except:
		brand_right_side = str(asoup_item).split('and ships from Amazon')  
		brand = brand_right_side[0].split('Sold by ')[-1] #
		brand = brand.replace(';',' ')

	# print('Name:', name)
	# print('Brand:', brand)
	# print('Price:', price)
	# print('Estimated sales per month:', sales) 
	# print('Estimated revenue per month:', revenue)
	# print('Reviews:', reviews)
	# print('Rating:', stars)



	table.append([name.replace(';',' '), brand.replace(';',' '), category, rank, reviews, stars, sales, revenue, price, ebay_price, link, ebay_url])

	with open(keyword.replace(' ', '_') + '_table' + str(pages) + '.csv','w', encoding = "utf-8-sig") as file:
		for _rows in table:
			for _coll in _rows:
				file.write(str(_coll)+';')
			file.write('\n')
	#print('='*20)
	# time.sleep(1)
