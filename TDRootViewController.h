#import <UIKit/UIKit.h>

@interface TDRootViewController : UITableViewController

@property (nonatomic, strong) NSArray *apps;
@property (nonatomic, strong) NSMutableDictionary *hookPrefs;
@property (nonatomic, copy) NSString *hookPrefsPath;
@property (nonatomic, strong) NSMutableDictionary *iconCache;

@end

