# Scrapy settings for regwatch project
# https://docs.scrapy.org/en/latest/topics/settings.html

BOT_NAME = "regwatch"

SPIDER_MODULES = ["regwatch.spiders"]
NEWSPIDER_MODULE = "regwatch.spiders"


# Respect robots.txt
ROBOTSTXT_OBEY = True

# Politeness / rate limit
CONCURRENT_REQUESTS_PER_DOMAIN = 1
DOWNLOAD_DELAY = 1

# Pipelines
ITEM_PIPELINES = {
    "regwatch.pipelines.PostgresUpsertPipeline": 300,
}

# Logging
LOG_LEVEL = "INFO"

# Future-proof export
FEED_EXPORT_ENCODING = "utf-8"

