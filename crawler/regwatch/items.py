import scrapy

class CandidateItem(scrapy.Item):
    source = scrapy.Field()
    official_url = scrapy.Field()
    official_date = scrapy.Field()  # "YYYY-MM-DD"
    title_raw = scrapy.Field()
    pdf_url = scrapy.Field()
