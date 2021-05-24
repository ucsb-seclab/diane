import os
import glob
import argparse
import worker


def run_sanity_check_analysis(pickle_dir):
    pickle_regex = os.path.join(pickle_dir, '*.pickle')
    analyses_scheduled = 0
    for pickled_app in glob.glob(pickle_regex):
        analyses_scheduled += 1
        worker.run_analysis.delay(pickled_app)
    
    print('Analyses scheduled: %d' % analyses_scheduled)


def run_pickling(app_dir):
    app_regex = os.path.join(app_dir, '*.apk')
    pickle_regex = os.path.join(app_dir, '*.pickle')
    pickled_app_names = list(map(lambda x: os.path.splitext(os.path.basename(x))[0], glob.glob(pickle_regex)))
    pickling_scheduled = 0
    for app in glob.glob(app_regex):
        app_name = os.path.splitext(os.path.basename(app))[0]
        if app_name not in pickled_app_names:
            pickling_scheduled += 1
            worker.run_lifting.delay(app)
    
    print('Pickling scheduled: %d' % pickling_scheduled)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Schedule sanity check analysis on Celery')
    subparsers = parser.add_subparsers(dest='command')
    pickle_parser = subparsers.add_parser('pickle', help='Pickle an APK')
    pickle_parser.add_argument('--app-dir', dest='app_dir', required=True, help='Directory containing apps and pickles')
    sanity_parser = subparsers.add_parser('analyze', help='Count sanity checks in an APK')
    sanity_parser.add_argument('--app-dir', dest='app_dir', required=True, help='Directory containing apps and pickles')
    args = parser.parse_args()

    if args.command == 'pickle':
        run_pickling(args.app_dir)
    elif args.command == 'analyze':
        run_sanity_check_analysis(args.app_dir)
    else:
        pass
