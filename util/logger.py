import logging

formatter = logging.Formatter('%(asctime)s %(levelname)s %(filename)s:%(lineno)d %(message)s')


def get_logger(name, level=0):
    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)
    if level == 1:
        logger.setLevel(logging.DEBUG)
    logger.propagate = False

    console_handler = logging.StreamHandler()
    if level == 1:
        console_handler.setLevel(logging.DEBUG)
    console_handler.setFormatter(formatter)

    logger.addHandler(console_handler)
    return logger
