package dev.okhsunrog.netdiag;

import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;

import java.util.List;

/**
 * The installed application list, for the per-app screen.
 *
 * <p>This is where the app's cross-layer story starts on the framework side:
 * the daemon reports sockets by uid, and a uid means nothing to a person until
 * it has a name. The daemon could read {@code /data/system/packages.list} for
 * the mapping, but only the framework knows the label a user would recognise.
 *
 * <p>In Rust this is a {@code List<ApplicationInfo>} plus a
 * {@code getApplicationLabel} call per entry — several hundred JNI round trips
 * and a page of binding declarations for what is four lines of Java. That is
 * why the per-app screen used to show only this app's own uid. Once
 * {@code cargo rapk} made adding a Java class free, putting it where it is
 * cheap became the obvious answer.
 *
 * <p>It is an object with a constructor rather than a static helper only
 * because {@code bind_java_type!} on the Rust side binds constructors and
 * instance methods, not static ones.
 *
 * <p>Like {@link NetdiagFrameworkWatcher} it carries no schema: the result is
 * one string and Rust parses it. Returning {@code String[]} would cost a JNI
 * call per element, which is the cost this class exists to avoid.
 */
public final class NetdiagPackages {

    private static final char FIELD = '\t';
    private static final char RECORD = '\n';

    private final PackageManager packages;

    public NetdiagPackages(Context context) {
        this.packages = context.getPackageManager();
    }

    /**
     * Every installed application as {@code uid \t system \t package \t label},
     * one per line.
     *
     * <p>Requires {@code QUERY_ALL_PACKAGES}; without it this returns only the
     * few packages visible to us, which is not a failure worth reporting
     * separately — the list is simply shorter.
     */
    public String list() {
        List<ApplicationInfo> installed = packages.getInstalledApplications(0);

        StringBuilder out = new StringBuilder(installed.size() * 64);
        for (ApplicationInfo info : installed) {
            boolean system = (info.flags & ApplicationInfo.FLAG_SYSTEM) != 0;

            // A label is arbitrary user-visible text and may contain the
            // separators; getApplicationLabel falls back to the package name.
            String label = sanitize(packages.getApplicationLabel(info).toString());

            out.append(info.uid)
                    .append(FIELD)
                    .append(system ? '1' : '0')
                    .append(FIELD)
                    .append(sanitize(info.packageName))
                    .append(FIELD)
                    .append(label)
                    .append(RECORD);
        }
        return out.toString();
    }

    private static String sanitize(String value) {
        return value.replace(FIELD, ' ').replace(RECORD, ' ');
    }
}
